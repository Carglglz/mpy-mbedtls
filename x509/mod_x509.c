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
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509.h"
#include "mbedtls/mbedtls_config.h"

struct gen_key_args {
    mp_arg_val_t ec_curve;
};

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

//parse_cert(b"")
static mp_obj_t x509_parse_cert(const mp_obj_t cert_in){
   
   mp_check_self(mp_obj_is_str_or_bytes(cert_in));
   
    // check if cert is a string/path
    mp_obj_t cert_data;
    if (!(mp_obj_is_type(cert_in, &mp_type_bytes))) {
        cert_data = read_file(cert_in);
    } else {
        cert_data = cert_in;
    }
   
   //init
   int ret;
   mbedtls_x509_crt crt;
   mbedtls_x509_crt *cur = &crt;
   mbedtls_x509_crt_init( &crt );
   unsigned char buf[1024];
   mp_obj_t list = mp_obj_new_list(0, NULL);
   
   // Parse cert
   size_t cert_len;
   const byte *cert = (const byte *)mp_obj_str_get_data(cert_data, &cert_len);
   // len should include terminating null
   ret = mbedtls_x509_crt_parse(&crt, cert, cert_len + 1);
   if (ret != 0) {
       ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA; // use general error for all cert errors
       goto cleanup;
   }
   while( cur != NULL )
   {
	 
	 ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, " ", cur );
	 if( ret == -1 )
	 {
	    goto cleanup;
	 }

	 mp_obj_list_append(list, MP_OBJ_FROM_PTR(mp_obj_new_bytes(buf, ret)));

	 cur = cur->next;
    }

    mbedtls_x509_crt_free( &crt );

    return list;

cleanup:
    	mbedtls_x509_crt_free(&crt);
	mbedtls_raise_error(ret);

}
MP_DEFINE_CONST_FUN_OBJ_1(x509_parse_cert_obj, x509_parse_cert);


//gen_csr(subject, key)
static mp_obj_t x509_gen_csr(const mp_obj_t sub_in, const mp_obj_t key_in, const mp_obj_t csr_name){

    mp_check_self(mp_obj_is_str_or_bytes(sub_in));
    mp_check_self(mp_obj_is_str_or_bytes(key_in));

    // check if key is a string/path
    mp_obj_t key_data;
    if (!(mp_obj_is_type(key_in, &mp_type_bytes))) {
        key_data = read_file(key_in);
    } else {
        key_data = key_in;
    }

    //init
    int ret;
    mbedtls_pk_context key;
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_x509write_csr_init( &req );
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    // MD ALGO SHA256
    mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );

    //KEY USAGE TLS Web server/client authentication
    mbedtls_x509write_csr_set_key_usage( &req,  MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT | 
		                         MBEDTLS_X509_KU_KEY_AGREEMENT);


    // mbedtls_x509write_csr_set_ns_cert_type( &req, MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

    // Seed PRNG
    const byte seed[] = "upy";
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, seed, sizeof(seed));
    if (ret != 0) {
        goto cleanup;
     }

    // Check Subject Name 
    const char *subject = mp_obj_str_get_str(sub_in);
    // a comma-separated list of OID types and values: e.g. "C=UK,O=ARM,CN=mbed TLS Server 1".
    ret =  mbedtls_x509write_csr_set_subject_name( &req, subject);
    if (ret != 0){
        goto cleanup;
    }
    
    //Parse private key
    size_t key_len;
    const byte *pkey = (const byte *)mp_obj_str_get_data(key_data, &key_len);
	#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    ret = mbedtls_pk_parse_key(&key, pkey, key_len + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
	#else
    ret = mbedtls_pk_parse_key(&key, pkey, key_len + 1, NULL, 0);
	#endif
    if (ret != 0) {
	    ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA; // use general error for all key errors
	    goto cleanup;
    }
    
    mbedtls_x509write_csr_set_key( &req, &key );

    // Writing CSR
    unsigned char output_buf[512];
    memset( output_buf, 0, 512 );
    size_t len = 0;
    ret = mbedtls_x509write_csr_pem( &req, output_buf, sizeof(output_buf) , mbedtls_ctr_drbg_random, &ctr_drbg );
    if (ret < 0){
    	goto cleanup;
    }

    len = strlen( (char *) output_buf );

    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mp_obj_t csr = mp_obj_new_bytes(output_buf, len);
    
    if (mp_obj_is_str_or_bytes(csr_name)){
        return write_file(csr_name, csr);
    }
    else {
        return csr;
    }


cleanup:
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_x509write_csr_free( &req );

	if (ret == MP_ENOMEM){
 		mp_raise_OSError(MP_ENOMEM);
	}

	else {
        	mbedtls_raise_error(ret);
	}

}
MP_DEFINE_CONST_FUN_OBJ_3(x509_gen_csr_obj, x509_gen_csr);


static mp_obj_t x509_verify_cert(const mp_obj_t cert_in, const mp_obj_t cacert_in){

    mp_check_self(mp_obj_is_str_or_bytes(cert_in));
    mp_check_self(mp_obj_is_str_or_bytes(cacert_in));

    // check if cert is a string/path
    mp_obj_t cert_data;
    if (!(mp_obj_is_type(cert_in, &mp_type_bytes))) {
        cert_data = read_file(cert_in);
    } else {
        cert_data = cert_in;
    }

    // check if cacert is a string/path
    mp_obj_t cacert_data;
    if (!(mp_obj_is_type(cacert_in, &mp_type_bytes))) {
        cacert_data = read_file(cacert_in);
    } else {
        cacert_data = cacert_in;
    }

    //init 
    int ret;
    uint32_t flags;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &crt );

   // Parse cacert
   size_t cacert_len;
   const byte *ca_cert = (const byte *)mp_obj_str_get_data(cacert_data, &cacert_len);
   // len should include terminating null
   ret = mbedtls_x509_crt_parse(&cacert, ca_cert, cacert_len + 1);
   if (ret != 0) {
       ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA; // use general error for all cert errors
       goto cleanup;
   }
   // Parse cert
   size_t cert_len;
   const byte *cert = (const byte *)mp_obj_str_get_data(cert_data, &cert_len);
   // len should include terminating null
   ret = mbedtls_x509_crt_parse(&crt, cert, cert_len + 1);
   if (ret != 0) {
       ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA; // use general error for all cert errors
       goto cleanup;
   }
   //Verify
   ret = mbedtls_x509_crt_verify( &crt, &cacert, NULL, NULL, &flags, NULL, NULL );
   if (ret != 0){
   	goto cleanup;
   }

   mbedtls_x509_crt_free( &cacert );
   mbedtls_x509_crt_free( &crt );

   return mp_const_true;

cleanup:
   	
	   
	mbedtls_x509_crt_free( &cacert );
	mbedtls_x509_crt_free( &crt );

	if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
       	    char xcbuf[512];
	    memset( xcbuf, 0, 512 );
            // printf("flags: %u \n", flags);
	    ret = mbedtls_x509_crt_verify_info(xcbuf, sizeof(xcbuf), "\n", flags);
	    //printf("buf size: %lu \n", sizeof(xcbuf));
	    //printf("str len: %lu \n", strlen((char *) xcbuf));
        // The length of the string written (not including the terminated nul byte),
        // or a negative err code.
        if (ret > 0) {
            mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("%s"), xcbuf);
        } 
        else {
            mbedtls_raise_error(ret);
        }
    }
	else {
	    mbedtls_raise_error(ret);
	}


}
MP_DEFINE_CONST_FUN_OBJ_2(x509_verify_cert_obj, x509_verify_cert);


static const mp_rom_map_elem_t mp_module_x509_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_x509) },
    { MP_ROM_QSTR(MP_QSTR_parse_cert), MP_ROM_PTR(&x509_parse_cert_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_cert), MP_ROM_PTR(&x509_verify_cert_obj) },
    { MP_ROM_QSTR(MP_QSTR_gen_csr), MP_ROM_PTR(&x509_gen_csr_obj) },
 
};

static MP_DEFINE_CONST_DICT(mp_module_x509_globals, mp_module_x509_globals_table);

const mp_obj_module_t mp_module_x509 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_x509_globals,
};

MP_REGISTER_MODULE(MP_QSTR_x509, mp_module_x509);


