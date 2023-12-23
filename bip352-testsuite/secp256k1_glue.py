from ctypes import *
import os

secplib = CDLL('../.libs/libsecp256k1.so')
secplib.secp256k1_context_create.restype = c_voidp
secp_context = secplib.secp256k1_context_create(1)

##################################
### API calls from secp256k1.h ###
##################################
SECP256K1_PUBKEY_STRUCT_SIZE = 64
"""
int secp256k1_ec_pubkey_create(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);
"""
secplib.secp256k1_ec_pubkey_create.argtypes = [c_voidp, c_voidp, c_voidp]
secplib.secp256k1_ec_pubkey_create.restype = c_int
def pubkey_create(privkey_bytes):
    pk = create_string_buffer(SECP256K1_PUBKEY_STRUCT_SIZE)
    retval = secplib.secp256k1_ec_pubkey_create(secp_context, pk, privkey_bytes)
    assert retval == 1
    return pk

"""
int secp256k1_ec_pubkey_parse(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);
"""
secplib.secp256k1_ec_pubkey_parse.argtypes = [c_voidp, c_voidp, c_voidp, c_size_t]
secplib.secp256k1_ec_pubkey_parse.restype = c_int
def pubkey_parse(pubkey_bytes):
    pk = create_string_buffer(SECP256K1_PUBKEY_STRUCT_SIZE)
    retval = secplib.secp256k1_ec_pubkey_parse(secp_context, pk, pubkey_bytes, 33)
    assert retval == 1
    return pk

"""
int secp256k1_ec_pubkey_serialize(
    const secp256k1_context *ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey *pubkey,
    unsigned int flags
);
"""
secplib.secp256k1_ec_pubkey_serialize.argtypes = [c_voidp, c_voidp, c_voidp, c_voidp, c_uint]
secplib.secp256k1_ec_pubkey_serialize.restype = c_int
def pubkey_serialize(pubkey_obj):
    ser_pubkey = create_string_buffer(33)
    ser_pubkey_size = c_size_t(33)
    retval = secplib.secp256k1_ec_pubkey_serialize(secp_context,
        ser_pubkey, pointer(ser_pubkey_size), pubkey_obj, (1 << 1) | (1 << 8))
    assert retval == 1
    return bytes(ser_pubkey)

"""
int secp256k1_ec_seckey_negate(
    const secp256k1_context *ctx,
    unsigned char *seckey
);
int secp256k1_ec_seckey_tweak_add(
    const secp256k1_context *ctx,
    unsigned char *seckey,
    const unsigned char *tweak32
);
"""
secplib.secp256k1_ec_seckey_negate.argtypes = [c_voidp, c_voidp]
secplib.secp256k1_ec_seckey_negate.restype = c_int
secplib.secp256k1_ec_seckey_tweak_add.argtypes = [c_voidp, c_voidp]
secplib.secp256k1_ec_seckey_tweak_add.restype = c_int
def seckey_subtract(seckey_lhs, seckey_rhs):
    seckey_to_sub = create_string_buffer(seckey_rhs, 32)
    retval = secplib.secp256k1_ec_seckey_negate(secp_context, seckey_to_sub)
    assert retval == 1
    seckey_result = create_string_buffer(seckey_lhs, 32)
    retval = secplib.secp256k1_ec_seckey_tweak_add(secp_context, seckey_result, seckey_to_sub)
    assert retval == 1
    return bytes(seckey_result)

############################################
### API calls from secp256k1_extrakeys.h ###
############################################
SECP256K1_XONLY_PUBKEY_STRUCT_SIZE = 64
"""
int secp256k1_xonly_pubkey_parse(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *pubkey,
    const unsigned char *input32
);
"""
secplib.secp256k1_xonly_pubkey_parse.argtypes = [c_voidp, c_voidp, c_voidp]
secplib.secp256k1_xonly_pubkey_parse.restype = c_int
def xonly_pubkey_parse(xonly_pubkey_bytes):
    xpk = create_string_buffer(SECP256K1_XONLY_PUBKEY_STRUCT_SIZE)
    retval = secplib.secp256k1_xonly_pubkey_parse(secp_context, xpk, xonly_pubkey_bytes)
    assert retval == 1
    return xpk

"""
secp256k1_xonly_pubkey_serialize(
    const secp256k1_context *ctx,
    unsigned char *output32,
    const secp256k1_xonly_pubkey *pubkey
);
"""
secplib.secp256k1_xonly_pubkey_serialize.argtypes = [c_voidp, c_voidp, c_voidp]
secplib.secp256k1_xonly_pubkey_serialize.restype = c_int
def xonly_pubkey_serialize(xpubkey_obj):
    ser_xpubkey = create_string_buffer(32)
    retval = secplib.secp256k1_xonly_pubkey_serialize(secp_context, ser_xpubkey, xpubkey_obj)
    assert retval == 1
    return bytes(ser_xpubkey)

#################################################
### API calls from secp256k1_silentpayments.h ###
#################################################
"""
int secp256k1_silentpayments_create_private_tweak_data(
    const secp256k1_context *ctx,
    unsigned char *tweak_data32,
    const unsigned char *plain_seckeys,
    size_t n_plain_seckeys,
    const unsigned char *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char *outpoint_lowest36
);
"""
secplib.secp256k1_silentpayments_create_private_tweak_data.argtypes = [
    c_voidp, c_voidp, c_voidp, c_size_t, c_voidp, c_size_t, c_voidp
]
secplib.secp256k1_silentpayments_send_create_shared_secret.restype = c_int
def silentpayments_create_private_tweak_data(plain_seckeys, xonly_seckeys, outpoint_lowest):
    ser_plain_seckeys = b''.join(plain_seckeys)
    if len(ser_plain_seckeys) == 0: ser_plain_seckeys = None
    ser_xonly_seckeys = b''.join(xonly_seckeys)
    if len(ser_xonly_seckeys) == 0: ser_xonly_seckeys = None

    result_tweak_data = create_string_buffer(32)
    retval = secplib.secp256k1_silentpayments_create_private_tweak_data(
        secp_context, result_tweak_data, ser_plain_seckeys, len(plain_seckeys),
        ser_xonly_seckeys, len(xonly_seckeys), outpoint_lowest)
    assert retval == 1

    return bytes(result_tweak_data)

"""
int secp256k1_silentpayments_send_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const unsigned char *tweak_data32,
    const secp256k1_pubkey *receiver_scan_pubkey
);
"""
secplib.secp256k1_silentpayments_send_create_shared_secret.argtypes = [
    c_voidp, c_voidp, c_voidp, c_voidp
]
secplib.secp256k1_silentpayments_send_create_shared_secret.restype = c_int
def silentpayments_send_create_shared_secret(tweak_data, receiver_scan_pubkey):
    # convert receiver pubkey to secp256k1 object
    receiver_scan_pubkey_obj = pubkey_parse(receiver_scan_pubkey)

    result_shared_secret = create_string_buffer(33)
    retval = secplib.secp256k1_silentpayments_send_create_shared_secret(
        secp_context, result_shared_secret, tweak_data, receiver_scan_pubkey_obj)
    assert retval == 1

    return bytes(result_shared_secret)

"""
int secp256k1_silentpayments_create_public_tweak_data(
    const secp256k1_context *ctx,
    secp256k1_pubkey *public_tweak_data,
    const secp256k1_pubkey *plain_pubkeys,
    size_t n_plain_pubkeys,
    const secp256k1_xonly_pubkey *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const unsigned char *outpoint_lowest36
);
"""
secplib.secp256k1_silentpayments_create_public_tweak_data.argtypes = [
    c_voidp, c_voidp, c_voidp, c_size_t, c_voidp, c_size_t, c_voidp
]
secplib.secp256k1_silentpayments_create_public_tweak_data.restype = c_int
def silentpayments_create_tweak_data(plain_pubkeys, xonly_pubkeys, outpoint_lowest):
    # convert raw plain pubkeys to secp256k1 pubkeys and concatenate them
    ser_plain_pubkeys = b''
    for plain_pubkey in plain_pubkeys:
        ser_plain_pubkeys += pubkey_parse(plain_pubkey)
    if len(ser_plain_pubkeys) == 0: ser_plain_pubkeys = None
    # convert raw x-only pubkeys to secp256k1 x-only pubkeys and concatenate them
    ser_xonly_pubkeys = b''
    for xonly_pubkey in xonly_pubkeys:
        ser_xonly_pubkeys += xonly_pubkey_parse(xonly_pubkey)
    if len(ser_xonly_pubkeys) == 0: ser_xonly_pubkeys = None

    result_tweak_data = create_string_buffer(SECP256K1_PUBKEY_STRUCT_SIZE)
    retval = secplib.secp256k1_silentpayments_create_public_tweak_data(
        secp_context, result_tweak_data, ser_plain_pubkeys, len(plain_pubkeys),
        ser_xonly_pubkeys, len(xonly_pubkeys), outpoint_lowest)
    assert retval == 1

    return result_tweak_data

"""
int secp256k1_silentpayments_receive_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const secp256k1_pubkey *public_tweak_data,
    const unsigned char *receiver_scan_seckey
);
"""
secplib.secp256k1_silentpayments_receive_create_shared_secret.argtypes = [
    c_voidp, c_voidp, c_voidp, c_voidp
]
secplib.secp256k1_silentpayments_receive_create_shared_secret.restype = c_int
def silentpayments_receive_create_shared_secret(tweak_data, receiver_scan_seckey):
    result_shared_secret = create_string_buffer(33)
    retval = secplib.secp256k1_silentpayments_receive_create_shared_secret(
        secp_context, result_shared_secret, tweak_data, receiver_scan_seckey)
    assert retval == 1
    return bytes(result_shared_secret)

"""
int secp256k1_silentpayments_create_label_tweak(
    const secp256k1_context *ctx,
    unsigned char *label_tweak32,
    const unsigned char *receiver_scan_seckey,
    unsigned int m
);
"""
secplib.secp256k1_silentpayments_create_label_tweak.argtypes = [
    c_voidp, c_voidp, c_voidp, c_uint
]
secplib.secp256k1_silentpayments_create_label_tweak.restype = c_int
def silentpayments_create_label_tweak(receiver_scan_seckey, m):
    result_label_tweak = create_string_buffer(32)
    retval = secplib.secp256k1_silentpayments_create_label_tweak(
        secp_context, result_label_tweak, receiver_scan_seckey, m)
    assert retval == 1
    return bytes(result_label_tweak)

"""
int secp256k1_silentpayments_create_address_spend_pubkey(
    const secp256k1_context *ctx,
    unsigned char *l_addr_spend_pubkey33,
    const secp256k1_pubkey *receiver_spend_pubkey,
    const unsigned char *label_tweak32
);
"""
secplib.secp256k1_silentpayments_create_address_spend_pubkey.argtypes = [
    c_voidp, c_voidp, c_voidp, c_voidp
]
secplib.secp256k1_silentpayments_create_address_spend_pubkey.restype = c_int
def silentpayments_create_address_spend_pubkey(receiver_spend_pubkey, label_tweak):
    result_address_spend_pubkey = create_string_buffer(33)
    # convert receiver pubkey to secp256k1 object
    receiver_spend_pubkey_obj = pubkey_parse(receiver_spend_pubkey)

    retval = secplib.secp256k1_silentpayments_create_address_spend_pubkey(
        secp_context, result_address_spend_pubkey, receiver_spend_pubkey_obj, label_tweak)
    assert retval == 1
    return bytes(result_address_spend_pubkey)

"""
int secp256k1_silentpayments_create_output_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *output_xonly_pubkey,
    const unsigned char *shared_secret33,
    const secp256k1_pubkey *receiver_spend_pubkey,
    unsigned int k,
    const unsigned char *label_tweak32
);
"""
secplib.secp256k1_silentpayments_create_output_pubkey.argtypes = [
    c_voidp, c_voidp, c_voidp, c_voidp, c_uint, c_voidp
]
secplib.secp256k1_silentpayments_create_output_pubkey.restype = c_int
def silentpayments_create_output_pubkey(shared_secret, receiver_spend_pubkey, k, label_tweak=None):
    result_xpubkey = create_string_buffer(SECP256K1_XONLY_PUBKEY_STRUCT_SIZE)
    # convert receiver pubkey to secp256k1 object
    receiver_spend_pubkey_obj = pubkey_parse(receiver_spend_pubkey)

    retval = secplib.secp256k1_silentpayments_create_output_pubkey(
        secp_context, result_xpubkey, shared_secret, receiver_spend_pubkey_obj, k, label_tweak)
    assert retval == 1

    # serialize and return resulting x-only pubkey
    output = create_string_buffer(32)
    retval = secplib.secp256k1_xonly_pubkey_serialize(secp_context, output, result_xpubkey)
    assert retval == 1

    return bytes(output)

"""
int secp256k1_silentpayments_create_output_seckey(
    const secp256k1_context *ctx,
    unsigned char *output_seckey,
    const unsigned char *shared_secret33,
    const unsigned char *receiver_spend_seckey,
    unsigned int k,
    const unsigned char *label_tweak32
);
"""
secplib.secp256k1_silentpayments_create_output_seckey.argtypes = [
    c_voidp, c_voidp, c_voidp, c_voidp, c_uint, c_voidp
]
secplib.secp256k1_silentpayments_create_output_seckey.restype = c_int
def silentpayments_create_output_seckey(shared_secret, receiver_spend_seckey, k, label_tweak=None):
    result_seckey = create_string_buffer(32)
    retval = secplib.secp256k1_silentpayments_create_output_seckey(
        secp_context, result_seckey, shared_secret, receiver_spend_seckey, k, label_tweak)
    assert retval == 1
    return bytes(result_seckey)
