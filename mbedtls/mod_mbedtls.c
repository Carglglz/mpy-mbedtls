#include "py/builtin.h"
#include "py/runtime.h"
#include "py/mpconfig.h"
#include "py/objstr.h"
#include "py/obj.h"
#include "py/stream.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "mbedtls/version.h"
#include "mbedtls/platform.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/mbedtls_config.h"

#define FORMAT_PEM              0
#define FORMAT_DER              1


STATIC NORETURN void mbedtls_raise_error(int err) {
    // _mbedtls_ssl_send and _mbedtls_ssl_recv (below) turn positive error codes from the
    // underlying socket into negative codes to pass them through mbedtls. Here we turn them
    // positive again so they get interpreted as the OSError they really are. The
    // cut-off of -256 is a bit hacky, sigh.
    if (err < 0 && err > -256) {
        mp_raise_OSError(-err);
    }

    #if defined(MBEDTLS_ERROR_C)
    // Including mbedtls_strerror takes about 1.5KB due to the error strings.
    // MBEDTLS_ERROR_C is the define used by mbedtls to conditionally include mbedtls_strerror.
    // It is set/unset in the MBEDTLS_CONFIG_FILE which is defined in the Makefile.

    // Try to allocate memory for the message
    #define ERR_STR_MAX 80  // mbedtls_strerror truncates if it doesn't fit
    mp_obj_str_t *o_str = m_new_obj_maybe(mp_obj_str_t);
    byte *o_str_buf = m_new_maybe(byte, ERR_STR_MAX);
    if (o_str == NULL || o_str_buf == NULL) {
        mp_raise_OSError(err);
    }

    // print the error message into the allocated buffer
    mbedtls_strerror(err, (char *)o_str_buf, ERR_STR_MAX);
    size_t len = strlen((char *)o_str_buf);

    // Put the exception object together
    o_str->base.type = &mp_type_str;
    o_str->data = o_str_buf;
    o_str->len = len;
    o_str->hash = qstr_compute_hash(o_str->data, o_str->len);
    // raise
    mp_obj_t args[2] = { MP_OBJ_NEW_SMALL_INT(err), MP_OBJ_FROM_PTR(o_str)};
    nlr_raise(mp_obj_exception_make_new(&mp_type_OSError, 2, 0, args));
    #else
    // mbedtls is compiled without error strings so we simply return the err number
    mp_raise_OSError(err); // err is typically a large negative number
    #endif
}


//version
STATIC const MP_DEFINE_STR_OBJ(mbedtls_version_obj, MBEDTLS_VERSION_STRING_FULL);


//ec_curves()
STATIC mp_obj_t mbedtls_ec_curves(void) {
    mp_obj_t curve_list = mp_obj_new_list(0, NULL);
    
    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_list();
    while( ( ++curve_info )->name != NULL ){
	mp_obj_list_append(curve_list, MP_OBJ_FROM_PTR(mp_obj_new_str(curve_info->name, strlen(curve_info->name))));
    }

    return curve_list;
}
MP_DEFINE_CONST_FUN_OBJ_0(mbedtls_ec_curves_obj, mbedtls_ec_curves);

//ec_curve_info("curve")
STATIC mp_obj_t mbedtls_ec_curve_info(const mp_obj_t o_in) {

    mp_check_self(mp_obj_is_str_or_bytes(o_in));
    const char *curve = mp_obj_str_get_str(o_in);
    const mbedtls_ecp_curve_info *curve_info;
    if ((curve_info = mbedtls_ecp_curve_info_from_name(curve)) == NULL )
    {
	// raise MP_ERROR
    	return mp_const_none;
    }
    mp_obj_t tuple[4] = {mp_obj_new_int(curve_info->grp_id), mp_obj_new_int(curve_info->tls_id),
                         mp_obj_new_int(curve_info->bit_size), 
			 mp_obj_new_str(curve_info->name, strlen(curve_info->name))};    
    
    return mp_obj_new_tuple(4, tuple);
}
MP_DEFINE_CONST_FUN_OBJ_1(mbedtls_ec_curve_info_obj, mbedtls_ec_curve_info);


//ec_gen_key("curve")
STATIC mp_obj_t mbedtls_ec_gen_key(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_curve, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_QSTR(MP_QSTR_secp256r1)} },
        { MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    const char *curve = mp_obj_str_get_str(args[0].u_obj);
    const int format = args[1].u_int;
	const mbedtls_ecp_curve_info *curve_info;
    if ((curve_info = mbedtls_ecp_curve_info_from_name(curve)) == NULL )
    {
	// raise MP_ERROR
    	mp_raise_ValueError(MP_ERROR_TEXT("ec curve not found"));
    }
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    //init 
    int ret;
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    int bits = curve_info->bit_size;
    unsigned char output_buf[bits];
	// unsigned char *c = output_buf;

    // Seed
    const byte seed[] = "upy";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, sizeof(seed));
    if (ret != 0) {
        goto cleanup;
     }
    //Generate the key
    if( ( ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) ) ) != 0 ){
    	goto cleanup;
    }
    
    ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) curve_info->grp_id,
                                   mbedtls_pk_ec( key ),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
       goto cleanup;
    }
    

    //Export key
    //int bits = curve_info->bit_size;
    //unsigned char output_buf[bits];
    size_t len = 0;
	mp_obj_t pkey;
    memset(output_buf, 0, bits);
	if (format == FORMAT_PEM){
    	if( ( ret = mbedtls_pk_write_key_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    	goto cleanup;

    	}
		len = strlen( (char *) output_buf );
 		pkey = mp_obj_new_bytes(output_buf, len);
	}
	else {
		mp_raise_ValueError(MP_ERROR_TEXT("NotImplementedError: DER format"));
	//	if( ( ret = mbedtls_pk_write_key_der( &key, output_buf, sizeof(output_buf) )) <= 0 ){
	//    	goto cleanup;

    //		}
	//	len = ret;
	//	c = output_buf + sizeof(output_buf) - len;
	//	pkey = mp_obj_new_bytes(c, len);

	}
    // len = strlen( (char *) output_buf );

    // mp_obj_t pkey = mp_obj_new_bytes(output_buf, len);

    // Export public key
	mp_obj_t pubkey;
    memset(output_buf, 0, bits);
	if (format == FORMAT_PEM){
    	if( ( ret = mbedtls_pk_write_pubkey_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    	goto cleanup;

    	}
		len = strlen( (char *) output_buf );
 		pubkey = mp_obj_new_bytes(output_buf, len);
	}
	else{
		mp_raise_ValueError(MP_ERROR_TEXT("NotImplementedError: DER format"));
//		unsigned char output_der[bits];
//
//		if( ( ret = mbedtls_pk_write_pubkey_der( &key, output_der, sizeof(output_der) )) <= 0 ){
//	    	goto cleanup;
//
//    	}
//		len = ret;
//		c = output_der + sizeof(output_der) - len;
//		pubkey = mp_obj_new_bytes(c, len);

	}
    //len = strlen( (char *) output_buf );

    // mp_obj_t pubkey = mp_obj_new_bytes(output_buf, len);

    mp_obj_t tuple[2] = {pkey, pubkey};

    // Clean up
    mbedtls_pk_free(&key); 
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return mp_obj_new_tuple(2, tuple);

	
cleanup:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ec_gen_key_obj, 0,  mbedtls_ec_gen_key);


//Derive public key
STATIC mp_obj_t mbedtls_ec_get_pubkey(const mp_obj_t key_in){
   
    mp_check_self(mp_obj_is_str_or_bytes(key_in));
   
    int ret; 
    mbedtls_pk_context key;
    mbedtls_pk_init( &key );


    //Parse private key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_in, &key_len);
    unsigned char output_buf[key_len];


    ret = mbedtls_pk_parse_key(&key, pkey, key_len + 1, NULL, 0);
    if (ret != 0) {
	    // ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }
	
    //Export key
    //unsigned char output_buf[key_len];
    size_t len = 0;
    memset(output_buf, 0, key_len);

    if( ( ret = mbedtls_pk_write_pubkey_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    goto cleanup;

    }
    len = strlen( (char *) output_buf );

    // Clean up
    mbedtls_pk_free(&key); 


    return mp_obj_new_bytes(output_buf, len);


cleanup:
	mbedtls_pk_free(&key);
	mbedtls_raise_error(ret);
	
}
MP_DEFINE_CONST_FUN_OBJ_1(mbedtls_ec_get_pubkey_obj, mbedtls_ec_get_pubkey);




// Sign
STATIC mp_obj_t mbedtls_ec_key_sign(const mp_obj_t key_in, const mp_obj_t data_in) {

    mp_check_self(mp_obj_is_str_or_bytes(key_in));
    mp_check_self(mp_obj_is_str_or_bytes(data_in));
    
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    //init 
    int ret;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    size_t olen = 0;
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    // Seed
    const byte seed[] = "upy";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, sizeof(seed));
    if (ret != 0) {
        goto cleanup;
     }
    //Parse private key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_in, &key_len);
    ret = mbedtls_pk_parse_key(&key, pkey, key_len + 1, NULL, 0);
    if (ret != 0) {
	    // ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }

    //Parse data
    size_t data_len;
    const byte *data = (const byte *)mp_obj_str_get_data(data_in, &data_len);


    // SHA-256 hash of data
    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), data, data_len, hash ) ) != 0 ){
    	goto cleanup;
    }

    //Sign data hash
    if( ( ret = mbedtls_pk_sign( &key, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ){
    	goto cleanup;
    }
     
    // Clean up
    mbedtls_pk_free(&key); 
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return mp_obj_new_bytes(buf, olen);

	
cleanup:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_2(mbedtls_ec_key_sign_obj, mbedtls_ec_key_sign);


// Verify
STATIC mp_obj_t mbedtls_ec_key_verify(const mp_obj_t key_in, const mp_obj_t data_in, const mp_obj_t sig_in) {

    mp_check_self(mp_obj_is_str_or_bytes(key_in));
    mp_check_self(mp_obj_is_str_or_bytes(data_in));
    mp_check_self(mp_obj_is_str_or_bytes(sig_in));

    
    mbedtls_pk_context key;
    //init 
    int ret;
    unsigned char hash[32]; 
    mbedtls_pk_init( &key );
    //Parse public key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_in, &key_len);
    ret = mbedtls_pk_parse_public_key(&key, pkey, key_len + 1);
    if (ret != 0) {
	    //ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }

    //Parse data
    size_t data_len;
    const byte *data = (const byte *)mp_obj_str_get_data(data_in, &data_len);

    //Parse sig
    size_t sig_len;
    const byte *sig = (const byte *)mp_obj_str_get_data(sig_in, &sig_len);


    // SHA-256 hash of data
    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), data, data_len, hash ) ) != 0 ){
    	goto cleanup;
    }

    //Verify data hash
    if( ( ret = mbedtls_pk_verify( &key, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len) != 0 )){
	    goto cleanup;
    	
    }
     
    // Clean up
    mbedtls_pk_free(&key); 
    
    return mp_const_true;
	
cleanup:
	mbedtls_pk_free(&key);
    mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_3(mbedtls_ec_key_verify_obj, mbedtls_ec_key_verify);



STATIC const mp_rom_map_elem_t mp_module_mbedtls_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_mbedtls) }, 
    { MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&mbedtls_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_curves), MP_ROM_PTR(&mbedtls_ec_curves_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_curve_info), MP_ROM_PTR(&mbedtls_ec_curve_info_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_gen_key), MP_ROM_PTR(&mbedtls_ec_gen_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_get_pubkey), MP_ROM_PTR(&mbedtls_ec_get_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_key_sign), MP_ROM_PTR(&mbedtls_ec_key_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_key_verify), MP_ROM_PTR(&mbedtls_ec_key_verify_obj) },
	{ MP_ROM_QSTR(MP_QSTR_FORMAT_PEM), MP_ROM_INT(FORMAT_PEM) },
	{ MP_ROM_QSTR(MP_QSTR_FORMAT_DER), MP_ROM_INT(FORMAT_DER) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_mbedtls_globals, mp_module_mbedtls_globals_table);

const mp_obj_module_t mp_module_mbedtls = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_mbedtls_globals,
};

MP_REGISTER_MODULE(MP_QSTR_mbedtls, mp_module_mbedtls);


