#include "py/builtin.h"
#include "py/runtime.h"
#include "py/mpconfig.h"
#include "py/objstr.h"
#include "py/obj.h"
#include "py/stream.h"
#include "py/reader.h"
#include "extmod/vfs.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "mbedtls/version.h"
#include "mbedtls/platform.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/mbedtls_config.h"

#define FORMAT_PEM              0
#define FORMAT_DER              1


// Helper functions
static NORETURN void mbedtls_raise_error(int err) {
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


static mp_obj_t read_file(mp_obj_t self_in) {
    // file = open(args[0], "rb")
    mp_obj_t f_args[2] = {
        self_in,
        MP_OBJ_NEW_QSTR(MP_QSTR_rb),
    };
    mp_obj_t file = mp_vfs_open(2, &f_args[0], (mp_map_t *)&mp_const_empty_map);

    // data = file.read()
    mp_obj_t dest[2];
    mp_load_method(file, MP_QSTR_read, dest);
    mp_obj_t data = mp_call_method_n_kw(0, 0, dest);

    // file.close()
    mp_stream_close(file);
    return data;
}


static mp_obj_t write_file(mp_obj_t self_in, mp_obj_t data_in) {
    // file = open(args[0], "rb")
    mp_obj_t f_args[2] = {
        self_in,
        MP_OBJ_NEW_QSTR(MP_QSTR_wb),
    };
    mp_obj_t file = mp_vfs_open(2, &f_args[0], (mp_map_t *)&mp_const_empty_map);

    // data = file.read()
    mp_obj_t dest[3];
    mp_load_method(file, MP_QSTR_write, dest);
    dest[2] = data_in;
    mp_obj_t n_bytes = mp_call_method_n_kw(1, 0, dest);

    // file.close()
    mp_stream_close(file);
    return n_bytes;
}

//version
static const MP_DEFINE_STR_OBJ(mbedtls_version_obj, MBEDTLS_VERSION_STRING_FULL);


//ec_curves()
static mp_obj_t mbedtls_ec_curves(void) {
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
static mp_obj_t mbedtls_ec_curve_info(const mp_obj_t o_in) {

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
static mp_obj_t mbedtls_ec_gen_key(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_curve, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_QSTR(MP_QSTR_secp256r1)} },
        { MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
        { MP_QSTR_pkey, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
        { MP_QSTR_pubkey, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} }, 
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
	unsigned char *c = output_buf;
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
    mp_obj_t key_pair[2];
    //int bits = curve_info->bit_size;
    //unsigned char output_buf[bits];
    size_t len = 0;
	mp_obj_t pkey;
    memset(output_buf, 0, bits);
	if (format == FORMAT_PEM){
		#if defined(MBEDTLS_PEM_WRITE_C)
    	if( ( ret = mbedtls_pk_write_key_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    	goto cleanup;

    	}
		len = strlen( (char *) output_buf );
 		pkey = mp_obj_new_bytes(output_buf, len);
		#endif
	}
	else {
		// mp_raise_ValueError(MP_ERROR_TEXT("NotImplementedError: DER format"));
		if( ( ret = mbedtls_pk_write_key_der( &key, output_buf, sizeof(output_buf) )) < 0 ){
	    	goto cleanup;

    		}
		len = ret;
		c = output_buf + sizeof(output_buf) - len;
		pkey = mp_obj_new_bytes(c, len);

	}

    if (mp_obj_is_str_or_bytes(args[2].u_obj)){

        mp_obj_t wr_sz = write_file(args[2].u_obj, pkey);
        key_pair[0] = wr_sz;
    }
    else{
        key_pair[0] = pkey;

    }
    // len = strlen( (char *) output_buf );

    // mp_obj_t pkey = mp_obj_new_bytes(output_buf, len);

    // Export public key
	mp_obj_t pubkey;
    memset(output_buf, 0, bits);
	if (format == FORMAT_PEM){
		#if defined(MBEDTLS_PEM_WRITE_C)
    	if( ( ret = mbedtls_pk_write_pubkey_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    	goto cleanup;

    	}
		len = strlen( (char *) output_buf );
 		pubkey = mp_obj_new_bytes(output_buf, len);
		#endif
	}
	else{
		// mp_raise_ValueError(MP_ERROR_TEXT("NotImplementedError: DER format"));
		unsigned char output_der[bits];
		unsigned char *cder = output_der;
		memset(output_der, 0, bits);

		if( ( ret = mbedtls_pk_write_pubkey_der( &key, output_der, sizeof(output_der) )) < 0 ){
	    	goto cleanup;

    	}
		len = ret;
		cder = output_der + sizeof(output_der) - len;
		pubkey = mp_obj_new_bytes(cder, len);

	}

    if (mp_obj_is_str_or_bytes(args[3].u_obj)){

        mp_obj_t wr_szpub = write_file(args[3].u_obj, pubkey);
        key_pair[1] = wr_szpub;
    }
    else {
        key_pair[1] = pubkey;
    }
    //len = strlen( (char *) output_buf );

    // mp_obj_t pubkey = mp_obj_new_bytes(output_buf, len);

    /* mp_obj_t tuple[2] = {pkey, pubkey}; */

    // Clean up
    mbedtls_pk_free(&key); 
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return mp_obj_new_tuple(2, key_pair);

	
cleanup:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ec_gen_key_obj, 0,  mbedtls_ec_gen_key);


//Derive public key
static mp_obj_t mbedtls_ec_get_pubkey(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_key, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
		{ MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
        { MP_QSTR_out, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
   
    // check if key is a string/path
    mp_obj_t key_data;
    if (!(mp_obj_is_type(args[0].u_obj, &mp_type_bytes))) {
        key_data = read_file(args[0].u_obj);
    } else {
        key_data = args[0].u_obj;
    }
   
    int ret; 
	int fmt = args[1].u_int;//mp_obj_get_int();

    mbedtls_pk_context key;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );


    //Parse private key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_data, &key_len);
    unsigned char output_buf[key_len];

	if (fmt == 0){
		key_len = key_len + 1;
	}

	#if MBEDTLS_VERSION_NUMBER >= 0x03000000

    ret = mbedtls_pk_parse_key(&key, pkey, key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
	#else 
    ret = mbedtls_pk_parse_key(&key, pkey, key_len, NULL, 0);
	#endif
    if (ret != 0) {
	    // ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }
	
    //Export key
    //unsigned char output_buf[key_len];
	mp_obj_t pubkey;
    size_t len = 0;
    memset(output_buf, 0, key_len);
	if (fmt == FORMAT_PEM){
		#if defined(MBEDTLS_PEM_WRITE_C)
    	if( ( ret = mbedtls_pk_write_pubkey_pem( &key, output_buf, sizeof(output_buf) )) != 0 ){
	    	goto cleanup;

    	}
		len = strlen( (char *) output_buf );
 		pubkey = mp_obj_new_bytes(output_buf, len);
		#endif
	}
	else{
		// mp_raise_ValueError(MP_ERROR_TEXT("NotImplementedError: DER format"));
		unsigned char output_der[key_len];
		unsigned char *cder = output_der;
		memset(output_der, 0, key_len);

		if( ( ret = mbedtls_pk_write_pubkey_der( &key, output_der, sizeof(output_der) )) < 0 ){
	    	goto cleanup;

    	}
		len = ret;
		cder = output_der + sizeof(output_der) - len;
		pubkey = mp_obj_new_bytes(cder, len);

	}

    // Clean up
    mbedtls_pk_free(&key); 

    if (mp_obj_is_str_or_bytes(args[2].u_obj)){

        return write_file(args[2].u_obj, pubkey);
         
    }
    return pubkey;


cleanup:
	mbedtls_pk_free(&key);
	mbedtls_raise_error(ret);
	
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ec_get_pubkey_obj, 1, mbedtls_ec_get_pubkey);


// Sign
static mp_obj_t mbedtls_ec_key_sign(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_key, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
        { MP_QSTR_data, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
        { MP_QSTR_out, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
		{ MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[1].u_obj));


    // check if key is a string/path
    mp_obj_t key_data;
    if (!(mp_obj_is_type(args[0].u_obj, &mp_type_bytes))) {
        key_data = read_file(args[0].u_obj);
    } else {
        key_data = args[0].u_obj;
    }


    mp_obj_t sig_data;
    if (!(mp_obj_is_type(args[1].u_obj, &mp_type_bytes))) {
        sig_data = read_file(args[1].u_obj);
    } else {
        sig_data = args[1].u_obj;
    }
    


	int fmt = args[3].u_int;
    
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
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_data, &key_len);
	if (fmt == 0){
		key_len = key_len + 1;
	}
	#if MBEDTLS_VERSION_NUMBER >= 0x03000000

    ret = mbedtls_pk_parse_key(&key, pkey, key_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
	#else
    ret = mbedtls_pk_parse_key(&key, pkey, key_len, NULL, 0);
	#endif
    if (ret != 0) {
	    // ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }

    //Parse data
    size_t data_len;
    const byte *data = (const byte *)mp_obj_str_get_data(sig_data, &data_len);


    // SHA-256 hash of data
    if( ( ret = mbedtls_md( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), data, data_len, hash ) ) != 0 ){
    	goto cleanup;
    }

    //Sign data hash
	
	#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if( ( ret = mbedtls_pk_sign( &key, MBEDTLS_MD_SHA256, hash, sizeof(hash), buf, sizeof(buf), &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ){
    	goto cleanup;
    }
	#else
    if( ( ret = mbedtls_pk_sign( &key, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ){
    	goto cleanup;
    }
	#endif
     
    // Clean up
    mbedtls_pk_free(&key); 
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mp_obj_t signed_data = mp_obj_new_bytes(buf, olen);

    if (mp_obj_is_str_or_bytes(args[2].u_obj)){

        mp_obj_t wr_sz = write_file(args[2].u_obj, signed_data);
        return wr_sz;

    }
    return signed_data;

	
cleanup:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ec_key_sign_obj, 2, mbedtls_ec_key_sign);


// Verify
static mp_obj_t mbedtls_ec_key_verify(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_key, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
        { MP_QSTR_data, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
		{ MP_QSTR_signature, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
		{ MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[1].u_obj));
	mp_check_self(mp_obj_is_str_or_bytes(args[2].u_obj));


    // check if key is a string/path
    mp_obj_t key_data;
    if (!(mp_obj_is_type(args[0].u_obj, &mp_type_bytes))) {
        key_data = read_file(args[0].u_obj);
    } else {
        key_data = args[0].u_obj;
    }


    mp_obj_t sig_data;
    if (!(mp_obj_is_type(args[1].u_obj, &mp_type_bytes))) {
        sig_data = read_file(args[1].u_obj);
    } else {
        sig_data = args[1].u_obj;
    }


    mp_obj_t signature_data;
    if (!(mp_obj_is_type(args[2].u_obj, &mp_type_bytes))) {
        signature_data = read_file(args[2].u_obj);
    } else {
        signature_data = args[2].u_obj;
    }

	int fmt = args[3].u_int;
    
    mbedtls_pk_context key;
    //init 
    int ret;
    unsigned char hash[32]; 
    mbedtls_pk_init( &key );
    //Parse public key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_data, &key_len);
	if (fmt == 0){
		key_len = key_len + 1;
	}

    ret = mbedtls_pk_parse_public_key(&key, pkey, key_len);
    if (ret != 0) {
	    //ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }

    //Parse data
    size_t data_len;
    const byte *data = (const byte *)mp_obj_str_get_data(sig_data, &data_len);

    //Parse sig
    size_t sig_len;
    const byte *sig = (const byte *)mp_obj_str_get_data(signature_data, &sig_len);


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
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ec_key_verify_obj, 3, mbedtls_ec_key_verify);


// ECDH SECRET
static mp_obj_t mbedtls_ecdh_secret(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {
        { MP_QSTR_key_ours, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
        { MP_QSTR_key_theirs, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none} },
		{ MP_QSTR_format, MP_ARG_INT | MP_ARG_INT, {.u_int = FORMAT_PEM} },
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[1].u_obj));

    
    mbedtls_ecdh_context ctx;
	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_context key_ours; // private key 

    mbedtls_pk_context key_theirs; // public key 
    //init 
    int ret;
	size_t olen;
    unsigned char secret[32]; 
	int fmt = args[2].u_int;

    mbedtls_ecdh_init( &ctx );
    mbedtls_pk_init( &key_ours );
    mbedtls_pk_init( &key_theirs );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    // Seed
    const byte seed[] = "upy";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, sizeof(seed));
    if (ret != 0) {
        goto cleanup;
     }
    //Parse private key
    size_t key_len_o;
    const byte *pkey = (const byte *)mp_obj_str_get_data(args[0].u_obj, &key_len_o);
	if (fmt == 0){
		key_len_o = key_len_o + 1;
	}
	#if MBEDTLS_VERSION_NUMBER >= 0x03000000

    ret = mbedtls_pk_parse_key(&key_ours, pkey, key_len_o, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
	#else
    ret = mbedtls_pk_parse_key(&key_ours, pkey, key_len_o, NULL, 0);
	#endif
    if (ret != 0) {
	    // ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }
    //Parse public key
    size_t key_len_t;
    const byte *pubkey = (const byte *)mp_obj_str_get_data(args[1].u_obj, &key_len_t);
	if (fmt == 0){
		key_len_t = key_len_t + 1;
	}

    ret = mbedtls_pk_parse_public_key(&key_theirs, pubkey, key_len_t);
    if (ret != 0) {
	    //ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }

	//Setup ECDH Context
	mbedtls_ecp_keypair *key_o = mbedtls_pk_ec(key_ours);							 // 
	ret = mbedtls_ecdh_get_params(&ctx, key_o, MBEDTLS_ECDH_OURS);
	if (ret != 0){
		goto cleanup;
	}

	mbedtls_ecp_keypair *key_t = mbedtls_pk_ec(key_theirs);							 // 
	ret = mbedtls_ecdh_get_params(&ctx, key_t, MBEDTLS_ECDH_THEIRS);

	if (ret != 0){
		goto cleanup;
	}

	//Calc Secret 
	ret = mbedtls_ecdh_calc_secret(&ctx, &olen, secret, sizeof(secret), mbedtls_ctr_drbg_random, &ctr_drbg );
     
	if (ret != 0){
		goto cleanup;
	}
    // Clean up
    mbedtls_pk_free(&key_ours);
    mbedtls_pk_free(&key_theirs);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
	mbedtls_ecdh_free(&ctx);

    
    return mp_obj_new_bytes(secret, olen);
	
cleanup:
	mbedtls_pk_free(&key_ours);
    mbedtls_pk_free(&key_theirs);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
	mbedtls_ecdh_free(&ctx);
    mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_ecdh_secret_obj, 2, mbedtls_ecdh_secret);

// AES

//ciphers()
static mp_obj_t mbedtls_aes_ciphers(void) {
    mp_obj_t cipher_list = mp_obj_new_list(0, NULL);
    const int *cipher_info;
    const mbedtls_cipher_info_t *cipher_name;
    cipher_info = mbedtls_cipher_list();
    while( *cipher_info ){
		cipher_name = mbedtls_cipher_info_from_type( *cipher_info); 
	#if MBEDTLS_VERSION_NUMBER >= 0x03000000

	mp_obj_list_append(cipher_list, MP_OBJ_FROM_PTR(mp_obj_new_str(cipher_name->private_name, strlen(cipher_name->private_name))));
	#else
	mp_obj_list_append(cipher_list, MP_OBJ_FROM_PTR(mp_obj_new_str(cipher_name->name, strlen(cipher_name->name))));
	#endif
	cipher_info++;
    }

    return cipher_list;
}
MP_DEFINE_CONST_FUN_OBJ_0(mbedtls_aes_ciphers_obj, mbedtls_aes_ciphers);

// AES ENCRYPT
static mp_obj_t mbedtls_aes_enc(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {
		
        { MP_QSTR_cipher, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_QSTR(MP_QSTR_AES128CCM)} },
        { MP_QSTR_key, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
        { MP_QSTR_iv, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
        { MP_QSTR_data, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
        { MP_QSTR_tag, MP_ARG_REQUIRED | MP_ARG_INT, {.u_int = 13 }},
        { MP_QSTR_add, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[1].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[2].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[3].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[5].u_obj));

    
	mbedtls_cipher_context_t ctx;
    //init 
    int ret;

	//Parse cipher
	size_t ciph_len;
    const char *cipher = (const char*)mp_obj_str_get_data(args[0].u_obj, &ciph_len);
    const mbedtls_cipher_info_t *cipher_info;	
    //Parse key
	size_t key_len;
    const unsigned char *key = (const unsigned char*)mp_obj_str_get_data(args[1].u_obj, &key_len);
    //Parse iv
	size_t iv_len; // 7-13 bytes
    const unsigned char *iv = (const unsigned char*)mp_obj_str_get_data(args[2].u_obj, &iv_len);
	
	size_t tag_len = args[4].u_int; // 7-13 bytes
    //Parse data
	size_t data_len;
    const unsigned char *data = (const unsigned char*)mp_obj_str_get_data(args[3].u_obj, &data_len);
	
    //Parse additional data
	size_t addata_len;
    const unsigned char *addata = (const unsigned char*)mp_obj_str_get_data(args[5].u_obj, &addata_len);
	// Encrypt
	
	unsigned char buf[data_len+tag_len];
    memset(buf, 0, data_len+tag_len);

    cipher_info = mbedtls_cipher_info_from_string( cipher );
	if(cipher_info == NULL){

    	mp_raise_ValueError(MP_ERROR_TEXT("cipher not found"));

	}
	mbedtls_cipher_type_t cp_type;

	#if MBEDTLS_VERSION_NUMBER >= 0x03000000
	cp_type = cipher_info->private_type;
	#else
	cp_type = cipher_info->type;
	#endif
	mbedtls_cipher_init( &ctx );
	mbedtls_cipher_setup( &ctx, cipher_info);

	ret = mbedtls_cipher_setkey( &ctx, (const unsigned char*) key, key_len * 8, MBEDTLS_ENCRYPT);
    if (ret != 0) {
	    goto cleanup;
    }

	size_t olen;
	if (cp_type == MBEDTLS_CIPHER_AES_128_CCM || cp_type == MBEDTLS_CIPHER_AES_192_CCM || 
			cp_type == MBEDTLS_CIPHER_AES_256_CCM  ){

		ret = mbedtls_cipher_auth_encrypt_ext( &ctx, iv, iv_len, addata, addata_len, data,
			   								data_len, buf, data_len + tag_len, &olen, tag_len );
		
		if (ret != 0) {
			goto cleanup;
		}
	}
	else{
		ret = mbedtls_cipher_crypt( &ctx, iv, iv_len, 
				data, data_len, buf, &olen); 

		if (ret != 0) {
			goto cleanup;
		}
    }
	mp_obj_t enc = mp_obj_new_bytes(buf, olen);
	/* mp_obj_t tagf = mp_obj_new_bytes(tag, tag_len); */
    /* mp_obj_t tuple[2] = {enc, tagf}; */
    // Clean up
	mbedtls_cipher_free( &ctx );

    return enc;

	
cleanup:

	mbedtls_cipher_free( &ctx );
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_aes_enc_obj, 5, mbedtls_aes_enc);


static mp_obj_t mbedtls_aes_dec(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
	
	static const mp_arg_t allowed_args[] = {

        { MP_QSTR_cipher, MP_ARG_OBJ | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_QSTR(MP_QSTR_AES128CCM)} },
        { MP_QSTR_key, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
        { MP_QSTR_iv, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
        { MP_QSTR_data, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none}},
        { MP_QSTR_tag, MP_ARG_REQUIRED | MP_ARG_INT, {.u_int = 13 }},
        { MP_QSTR_add, MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_rom_obj = mp_const_none }},
    };

    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);


    mp_check_self(mp_obj_is_str_or_bytes(args[0].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[1].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[2].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[3].u_obj));
    mp_check_self(mp_obj_is_str_or_bytes(args[5].u_obj));

    
	mbedtls_cipher_context_t ctx;
    //init 
    int ret;
	//Parse cipher
	size_t ciph_len;
    const char *cipher = (const char*)mp_obj_str_get_data(args[0].u_obj, &ciph_len);
    const mbedtls_cipher_info_t *cipher_info;	
    //Parse key
	size_t key_len;
    const unsigned char *key = (const unsigned char*)mp_obj_str_get_data(args[1].u_obj, &key_len);
    //Parse iv
	size_t iv_len; // 7-13 bytes
    const unsigned char *iv = (const unsigned char*)mp_obj_str_get_data(args[2].u_obj, &iv_len);

    //Parse data
	size_t data_len;
    const unsigned char *data = (const unsigned char*)mp_obj_str_get_data(args[3].u_obj, &data_len);

	size_t tag_len = args[4].u_int; // 7-13 bytes
    /* unsigned char *tag = ( unsigned char*)mp_obj_str_get_data(args[4].u_obj, &tag_len); */

    //Parse additional data
	size_t addata_len;
    const unsigned char *addata = (const unsigned char*)mp_obj_str_get_data(args[5].u_obj, &addata_len);

	unsigned char buf[data_len];


    cipher_info = mbedtls_cipher_info_from_string( cipher );
	if(cipher_info == NULL){

    	mp_raise_ValueError(MP_ERROR_TEXT("cipher not found"));

	}

	mbedtls_cipher_type_t cp_type;

	#if MBEDTLS_VERSION_NUMBER >= 0x03000000
	cp_type = cipher_info->private_type;
	#else
	cp_type = cipher_info->type;
	#endif

	mbedtls_cipher_init( &ctx );
	mbedtls_cipher_setup( &ctx, cipher_info);


	ret = mbedtls_cipher_setkey( &ctx, (const unsigned char*) key, key_len * 8, MBEDTLS_DECRYPT);
    if (ret != 0) {
	    goto cleanup;
    }

	
	// Decrypt
	
    memset(buf, 0, data_len);
	/* size_t olen; */
	/* ret = mbedtls_cipher_auth_decrypt( &ctx, iv, iv_len, addata, addata_len, data, data_len, buf, &olen, tag, tag_len ); */
     
    /* if (ret != 0) { */
	/*     goto cleanup; */
    /* } */
    // Clean up
	
	size_t olen;
	if (cp_type == MBEDTLS_CIPHER_AES_128_CCM || cp_type == MBEDTLS_CIPHER_AES_192_CCM || 
			cp_type == MBEDTLS_CIPHER_AES_256_CCM  ){

		ret = mbedtls_cipher_auth_decrypt_ext( &ctx, iv, iv_len, addata, addata_len, data,
			   								data_len, buf, data_len + tag_len, &olen, tag_len );
		
		if (ret != 0) {
			goto cleanup;
		}
	}
	else{
		ret = mbedtls_cipher_crypt( &ctx, iv, iv_len, 
				data, data_len, buf, &olen); 

		if (ret != 0) {
			goto cleanup;
		}
    }

	mbedtls_cipher_free( &ctx );

    return mp_obj_new_bytes(buf, olen);

	
cleanup:

	mbedtls_cipher_free( &ctx );
	mbedtls_raise_error(ret);
}
MP_DEFINE_CONST_FUN_OBJ_KW(mbedtls_aes_dec_obj, 6, mbedtls_aes_dec);

static const mp_rom_map_elem_t mp_module_mbedtls_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_mbedtls) }, 
    { MP_ROM_QSTR(MP_QSTR_version), MP_ROM_PTR(&mbedtls_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_curves), MP_ROM_PTR(&mbedtls_ec_curves_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_curve_info), MP_ROM_PTR(&mbedtls_ec_curve_info_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_gen_key), MP_ROM_PTR(&mbedtls_ec_gen_key_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_get_pubkey), MP_ROM_PTR(&mbedtls_ec_get_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_key_sign), MP_ROM_PTR(&mbedtls_ec_key_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_ec_key_verify), MP_ROM_PTR(&mbedtls_ec_key_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdh_secret), MP_ROM_PTR(&mbedtls_ecdh_secret_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_encrypt), MP_ROM_PTR(&mbedtls_aes_enc_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_decrypt), MP_ROM_PTR(&mbedtls_aes_dec_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_ciphers), MP_ROM_PTR(&mbedtls_aes_ciphers_obj) },
	{ MP_ROM_QSTR(MP_QSTR_FORMAT_PEM), MP_ROM_INT(FORMAT_PEM) },
	{ MP_ROM_QSTR(MP_QSTR_FORMAT_DER), MP_ROM_INT(FORMAT_DER) },
};

static MP_DEFINE_CONST_DICT(mp_module_mbedtls_globals, mp_module_mbedtls_globals_table);

const mp_obj_module_t mp_module_mbedtls = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_mbedtls_globals,
};

MP_REGISTER_MODULE(MP_QSTR_mbedtls, mp_module_mbedtls);


