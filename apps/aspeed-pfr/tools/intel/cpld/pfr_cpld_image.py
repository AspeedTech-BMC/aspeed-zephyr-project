#!/usr/bin/env python3

"""
Copyright (c) 2023 ASPEED Technology Inc.

SPDX-License-Identifier: MIT
"""

import os
import sys
import xml.etree.ElementTree as et
import xmltodict
import json
import ecdsa
import ctypes

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Util.number import long_to_bytes

# Signing Section
XML_BLK_SIGN = "blocksign"
XML_VERSION = "version"
XML_BLK0 = "block0"
XML_BLK1 = "block1"
XML_MAGIC = "magic"
XML_CURV_MAGIC = "curvemagic"
XML_PC_TYPE = "pctype"
XML_PERMISSIONS = "permissions"
XML_KEY_ID = "keyid"
XML_PUB_KEY = "pubkey"
XML_RKEY = "rkey"
XML_CSKEY = "cskey"
XML_SIG_MAGIC = "sigmagic"
XML_HASH_ALG = "hashalg"
XML_SIGN_KEY = "signkey"
XML_B0_SIG = "b0_sig"

# CPLD Image Section
XML_CPLD_IMG_SECTION = "cpld_img_section"
XML_PFM = "pfm"
XML_CFM = "cfm"
XML_SVN = "svn"
XML_BKC_VER = "bkc_ver"
XML_MAJ_VER = "maj_ver"
XML_MIN_VER = "min_ver"
XML_DEV_ID = "dev_id"
XML_FW_TYPE = "fw_type"
XML_IMAGE = "image"
XML_OEM_DATA = "oem_data"

# Magic Number
PFM_MAGIC = 0x02b3ce1d
CFM_MAGIC = 0xa8e7c2d6


FW_TYPE_CPU_CPLD = "0"
FW_TYPE_SCM_CPLD = "1"
FW_TYPE_DEBUG_CPLD = "2"

PROP_IMAGE = "image"
PROP_IMAGE_SIZE = "size"
PROP_IMAGE_TYPE = "type"

# Start address of CPLD images
# Capsule Signature(1KB)
# PFM Signature(1KB)
# PFM (4KB)
# Reserved(2KB) for making image start address be 4kb aligned
CPLD_IMAGE_START_ADDRESS = 8192

# Block 0
class b0_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('pc_length', ctypes.c_uint),
                ('pc_type', ctypes.c_uint),
                ('reserved', ctypes.c_uint),
                ('hash256', ctypes.c_ubyte * 32),
                ('hash384', ctypes.c_ubyte * 48),
                ('reserved2', ctypes.c_ubyte * 32)]

    def __init__(self, magic, pc_length, pc_type, hash256, hash384):
        self.magic = magic
        self.pc_length = pc_length
        self.pc_type = pc_type
        ctypes.memmove(ctypes.byref(self.hash256), hash256, ctypes.sizeof(self.hash256))
        ctypes.memmove(ctypes.byref(self.hash384), hash384, ctypes.sizeof(self.hash384))


# Block 1 Root Entry
class b1_root_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('curve_magic', ctypes.c_uint),
                ('permissions', ctypes.c_uint),
                ('key_id', ctypes.c_uint),
                ('pubkey_x', ctypes.c_ubyte * 48),
                ('pubkey_y', ctypes.c_ubyte * 48),
                ('reserved', ctypes.c_ubyte * 20)]

    def __init__(self, magic, curve_magic, permissions, key_id, pubkey_x, pubkey_y):
        self.magic = magic
        self.curve_magic = curve_magic
        self.permissions = permissions
        self.key_id = key_id
        ctypes.memmove(ctypes.byref(self.pubkey_x), pubkey_x, ctypes.sizeof(self.pubkey_x))
        ctypes.memmove(ctypes.byref(self.pubkey_y), pubkey_y, ctypes.sizeof(self.pubkey_y))

# Block 1 CSK Entry
class b1_csk_pubkey_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('curve_magic', ctypes.c_uint),
                ('permissions', ctypes.c_uint),
                ('key_id', ctypes.c_uint),
                ('pubkey_x', ctypes.c_ubyte * 48),
                ('pubkey_y', ctypes.c_ubyte * 48),
                ('reserved', ctypes.c_ubyte * 20)]

    def __init__(self, curve_magic, permissions, key_id, pubkey_x, pubkey_y):
        self.curve_magic = curve_magic
        self.permissions = permissions
        self.key_id = key_id
        ctypes.memmove(ctypes.byref(self.pubkey_x), pubkey_x, ctypes.sizeof(self.pubkey_x))
        ctypes.memmove(ctypes.byref(self.pubkey_y), pubkey_y, ctypes.sizeof(self.pubkey_y))

class b1_csk_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('pubkey', b1_csk_pubkey_struct),
                ('sig_magic', ctypes.c_uint),
                ('sig_r', ctypes.c_ubyte * 48),
                ('sig_s', ctypes.c_ubyte * 48)]

    def __init__(self, magic, pubkey, sig_magic, sig_r, sig_s):
        self.magic = magic
        self.pubkey = pubkey
        self.sig_magic = sig_magic
        ctypes.memmove(ctypes.byref(self.sig_r), sig_r, ctypes.sizeof(self.sig_r))
        ctypes.memmove(ctypes.byref(self.sig_s), sig_s, ctypes.sizeof(self.sig_s))


# Block 1 Block 0 Entry
class b1_b0_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('sig_magic', ctypes.c_uint),
                ('sig_r', ctypes.c_ubyte * 48),
                ('sig_s', ctypes.c_ubyte * 48)]

    def __init__(self, magic, sig_magic, sig_r, sig_s):
        self.magic = magic
        self.sig_magic = sig_magic
        ctypes.memmove(ctypes.byref(self.sig_r), sig_r, ctypes.sizeof(self.sig_r))
        ctypes.memmove(ctypes.byref(self.sig_s), sig_s, ctypes.sizeof(self.sig_s))

# Block 1
class b1_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('reserved', ctypes.c_ubyte * 12),
                ('root_entry', b1_root_struct),
                ('csk_entry', b1_csk_struct),
                ('b0_entry', b1_b0_struct)]

    def __init__(self, magic, root_entry, csk_entry, b0_entry):
        self.magic = magic
        self.root_entry = root_entry
        self.csk_entry = csk_entry
        self.b0_entry = b0_entry

# Signature Data Structure
class signature_struct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('block0', b0_struct),
                ('block1', b1_struct),
                ('padding', ctypes. c_ubyte * \
                    (1024 - ctypes.sizeof(b0_struct) - ctypes.sizeof(b1_struct)))]

    def __init__(self, block0, block1):
        self.block0 = block0
        self.block1 = block1

SIGNATURE_SIZE = ctypes.sizeof(signature_struct)

# CPLD Firmware Manifest Address Definition
class cfm_ad_stuct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('fm_def_type', ctypes.c_ubyte),
                ('fw_type', ctypes.c_ushort),
                ('reserved', ctypes.c_ubyte),
                ('length', ctypes.c_uint),
                ('image_start_offset', ctypes.c_uint)]

    def __init__(self, fw_type, length, image_start_offset):
        # CPLD FM definition type: 0x3 - PFM SPI region address/offset definition
        self.fm_def_type = 0x3
        self.fw_type = fw_type
        self.length = length
        self.image_start_offset = image_start_offset
        self.reserved = 0xff

# CPLD Firmware Manifest
class cfm_header_stuct(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic', ctypes.c_uint),
                ('svn', ctypes.c_ubyte),
                ('reserved', ctypes.c_ubyte),
                ('maj_ver', ctypes.c_ubyte),
                ('min_ver', ctypes.c_ubyte),
                ('reserved2', ctypes.c_ushort),
                ('fw_type', ctypes.c_ushort),
                ('oem_data', ctypes.c_ubyte * 16),
                ('length', ctypes.c_uint)]

    def __init__(self, svn, maj_ver, min_ver, fw_type, oem_data, length):
        self.magic = CFM_MAGIC
        self.svn = svn
        self.maj_ver = maj_ver
        self.min_ver = min_ver
        self.fw_type = fw_type
        self.length = length
        self.reserved = 0xff
        self.reserved2 = 0xffff
        ctypes.memset(ctypes.byref(self.oem_data), 0xff, ctypes.sizeof(self.oem_data))
        if (oem_data is not None):
            ctypes.memmove(ctypes.byref(self.oem_data), oem_data, len(oem_data))

def load_xml(xml):
    with open(xml) as fd:
        xml_dict = xmltodict.parse(fd.read())

    return xml_dict

def print_usage():
    print("Usage: {0} <XML file>".format(sys.argv[0]))
    sys.exit (1)

def gen_indv_cpld_image(svn, maj_ver, min_ver, fw_type, oem_data, cpld_img_path):
    with open(cpld_img_path, 'rb') as fd:
        cpld_image = fd.read()
    image_size = os.stat(cpld_img_path).st_size
    padding_size = 4096 - ((SIGNATURE_SIZE + ctypes.sizeof(cfm_header_stuct) + image_size) % 4096)

    class indiviual_cpld_image_struct(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('cfm_header', cfm_header_stuct),
                    ('cpld_image', ctypes.c_ubyte * image_size),
                    ('padding', ctypes.c_ubyte * padding_size)]

        def __init__(self, cfm_header, cpld_image):
            self.cfm_header = cfm_header
            ctypes.memmove(ctypes.byref(self.cpld_image), cpld_image, ctypes.sizeof(self.cpld_image))
            ctypes.memset(ctypes.byref(self.padding), 0xff, ctypes.sizeof(self.padding))

    cfm_header = cfm_header_stuct(svn, maj_ver, min_ver, fw_type, oem_data, image_size)

    return indiviual_cpld_image_struct(cfm_header, cpld_image)

def sign_image(xml_dict, image):
    # 1. Generate Block0
    cfg_b0 = xml_dict[XML_BLK_SIGN][XML_BLK0]
    h256 = SHA256.new(image)
    h384 = SHA384.new(image)
    b0_magic = int(cfg_b0[XML_MAGIC], 16)
    b0_pc_len = len(image)
    b0_pc_type = int(cfg_b0[XML_PC_TYPE])
    b0_inst = b0_struct(b0_magic, b0_pc_len, b0_pc_type, h256.digest(), h384.digest())


    # 2. Generate Block1
    cfg_b1 = xml_dict[XML_BLK_SIGN][XML_BLK1]
    # 2-1. Generate Block1 Root Key Entry
    cfg_b1_rk = cfg_b1[XML_RKEY]
    rk_magic = int(cfg_b1_rk[XML_MAGIC], 16)
    rk_curv_magic = int(cfg_b1_rk[XML_CURV_MAGIC], 16)
    rk_permissions = int(cfg_b1_rk[XML_PERMISSIONS])
    rk_key_id = int(cfg_b1_rk[XML_KEY_ID])
    rk_pubkey = cfg_b1_rk[XML_PUB_KEY]
    try:
        rkey = ECC.import_key(open(rk_pubkey).read())
    except Exception:
        print(exception)

    point = rkey.pointQ
    rk_pubkey_x = long_to_bytes(point.x)
    rk_pubkey_y = long_to_bytes(point.y)

    b1_root_inst = b1_root_struct(rk_magic, rk_curv_magic, rk_permissions, rk_key_id,
            rk_pubkey_x, rk_pubkey_y)

    # 2-2. Generate Block1 CSK Entry
    cfg_b1_csk = cfg_b1[XML_CSKEY]
    csk_magic = int(cfg_b1_csk[XML_MAGIC], 16)
    csk_curv_magic = int(cfg_b1_csk[XML_CURV_MAGIC], 16)
    csk_permissions = int(cfg_b1_csk[XML_PERMISSIONS])
    csk_key_id = int(cfg_b1_csk[XML_KEY_ID])
    csk_pubkey = cfg_b1_csk[XML_PUB_KEY]
    csk_sign_key = cfg_b1_csk[XML_SIGN_KEY]
    csk_hash_alg = cfg_b1_csk[XML_HASH_ALG]
    csk_sigmagic = int(cfg_b1_csk[XML_SIG_MAGIC], 16)

    try:
        cskey = ECC.import_key(open(csk_pubkey).read())
    except Exception:
        print(exception)

    point = cskey.pointQ
    csk_pubkey_x = long_to_bytes(point.x)
    csk_pubkey_y = long_to_bytes(point.y)
    csk_pubkey_inst = b1_csk_pubkey_struct(csk_curv_magic, csk_permissions, csk_key_id,
            csk_pubkey_x, csk_pubkey_y)

    if csk_hash_alg == "sha256" or csk_hash_alg == "SHA256":
        h256 = SHA256.new(bytearray(csk_pubkey_info))
        csk_hash_buf = h256
    elif csk_hash_alg == "sha384" or csk_hash_alg == "SHA384":
        h384 = SHA384.new(bytearray(csk_pubkey_inst))
        csk_hash_buf = h384

    try:
        csk_signing_key = ECC.import_key(open(csk_sign_key).read())
    except Exception:
        print(exception)

    signer = DSS.new(csk_signing_key, 'fips-186-3')
    signature = signer.sign(csk_hash_buf)
    sig_rs_len = len(signature) // 2
    sig_r = signature[:sig_rs_len]
    sig_s = signature[sig_rs_len:]
    b1_csk_inst = b1_csk_struct(csk_magic, csk_pubkey_inst, csk_sigmagic, sig_r, sig_s)

    # 2-3. Generate Block1's Block0 Entry
    cfg_b1_b0 = cfg_b1[XML_B0_SIG]
    b1_b0_magic = int(cfg_b1_b0[XML_MAGIC], 16)
    b1_b0_sig_magic = int(cfg_b1_b0[XML_SIG_MAGIC], 16)
    b1_b0_hash_alg = cfg_b1_b0[XML_HASH_ALG]
    b1_b0_sign_key = cfg_b1_b0[XML_SIGN_KEY]

    if csk_hash_alg == "sha256" or csk_hash_alg == "SHA256":
        h256 = SHA256.new(bytearray(b0_inst))
        b0_hash_buf = h256
    elif csk_hash_alg == "sha384" or csk_hash_alg == "SHA384":
        h384 = SHA384.new(bytearray(b0_inst))
        b0_hash_buf = h384

    try:
        b0_signing_key = ECC.import_key(open(b1_b0_sign_key).read())
    except Exception:
        print(exception)

    signer = DSS.new(b0_signing_key, 'fips-186-3')
    signature = signer.sign(b0_hash_buf)
    sig_rs_len = len(signature) // 2
    sig_r = signature[:sig_rs_len]
    sig_s = signature[sig_rs_len:]
    b1_b0_inst = b1_b0_struct(b1_b0_magic, b1_b0_sig_magic, sig_r, sig_s)

    # 2-4. Construct signature chain
    b1_magic = int(cfg_b1[XML_MAGIC], 16)
    b1_inst = b1_struct(b1_magic, b1_root_inst, b1_csk_inst, b1_b0_inst)

    # 3. Construct Block0 and Block1 into signature data structure
    signature_inst = signature_struct(b0_inst, b1_inst)

    return bytearray(signature_inst) + image

def gen_indv_cpld_images(xml_dict):
    total_image_size = 0
    cfg_cfms = xml_dict[XML_BLK_SIGN][XML_CPLD_IMG_SECTION][XML_CFM]
    if (type(cfg_cfms) == dict):
        cfms = [cfg_cfms]
    elif (type(cfg_cfms) == list):
        cfms = cfg_cfms
    else:
        raise ValueError("Invalid CFM definition in xml, expect list or dict got {0}".format(type(cfg_cfms)))

    signed_cpld_imgs = []
    signed_cpld_img = {}

    for cfm in cfms:
        svn = int(cfm[XML_SVN])
        maj_ver = int(cfm[XML_MAJ_VER])
        min_ver = int(cfm[XML_MIN_VER])
        fw_type = int(cfm[XML_FW_TYPE])
        image = cfm[XML_IMAGE]
        oem_data = None
        if (cfm[XML_OEM_DATA] is not None):
            oem_data = bytes.fromhex(cfm[XML_OEM_DATA][2:])
            oem_data_len = len(oem_data)
            if oem_data_len > 16:
                raise ValueError("lengh of oem_data is {0}, exceed the maximum length 16".format( \
                        oem_data_len))

        cpld_img = gen_indv_cpld_image(svn, maj_ver, min_ver, fw_type,
                oem_data, image)
        signed_cpld_img[PROP_IMAGE] = sign_image(xml_dict, bytearray(cpld_img))
        signed_cpld_img[PROP_IMAGE_SIZE] = len(signed_cpld_img[PROP_IMAGE])
        signed_cpld_img[PROP_IMAGE_TYPE] = int(cfm[XML_FW_TYPE])
        signed_cpld_imgs.append(signed_cpld_img)
        total_image_size += signed_cpld_img[PROP_IMAGE_SIZE]

    return signed_cpld_imgs, total_image_size

def gen_pfm_image(xml_dict, cpld_imgs):
    img_start_address = CPLD_IMAGE_START_ADDRESS
    pfm_body = b""

    for cpld_img in cpld_imgs:
        cfm_ad_inst = cfm_ad_stuct(cpld_img[PROP_IMAGE_TYPE], cpld_img[PROP_IMAGE_SIZE],
                img_start_address)
        img_start_address += cpld_img[PROP_IMAGE_SIZE]
        pfm_body += bytearray(cfm_ad_inst)

    cfg_pfm = xml_dict[XML_BLK_SIGN][XML_CPLD_IMG_SECTION][XML_PFM]
    pfm_svn = int(cfg_pfm[XML_SVN])
    pfm_bkc = int(cfg_pfm[XML_BKC_VER])
    pfm_maj = int(cfg_pfm[XML_MAJ_VER])
    pfm_min = int(cfg_pfm[XML_MIN_VER])
    pfm_devid = int(cfg_pfm[XML_DEV_ID], 16)
    oem_data = None

    if (cfg_pfm[XML_OEM_DATA] is not None):
        oem_data = bytes.fromhex(cfg_pfm[XML_OEM_DATA][2:])
        oem_data_len = len(oem_data)
        if oem_data_len > 16:
            raise ValueError("lengh of oem_data is {0}, exceed the maximum length 16".format( \
                    oem_data_len))

    # Platform Firmware Manifest
    class pfm_stuct(ctypes.LittleEndianStructure):
        _pack_ = 1
        _fields_ = [('magic', ctypes.c_uint),
                    ('svn', ctypes.c_ubyte),
                    ('bkc_ver', ctypes.c_ubyte),
                    ('maj_ver', ctypes.c_ubyte),
                    ('min_ver', ctypes.c_ubyte),
                    ('dev_id', ctypes.c_ushort),
                    ('reserved', ctypes.c_ushort),
                    ('oem_data', ctypes.c_ubyte * 16),
                    ('length', ctypes.c_uint),
                    ('pfm_body', ctypes.c_ubyte * len(pfm_body))]

        def __init__(self, svn, bkc_ver, maj_ver, min_ver, dev_id, oem_data, pfm_body):
            self.magic = PFM_MAGIC
            self.svn = svn
            self.bkc_ver = bkc_ver
            self.maj_ver = maj_ver
            self.min_ver = min_ver
            self.dev_id = dev_id
            self.reserved = 0xffff
            ctypes.memset(ctypes.byref(self.oem_data), 0xff, ctypes.sizeof(self.oem_data))
            if (oem_data is not None):
                ctypes.memmove(ctypes.byref(self.oem_data), oem_data, len(oem_data))

            ctypes.memmove(ctypes.byref(self.pfm_body), pfm_body, len(pfm_body))

    pfm_inst = pfm_stuct(pfm_svn, pfm_bkc, pfm_maj, pfm_min, pfm_devid, oem_data, pfm_body)
    pfm_size = ctypes.sizeof(pfm_inst)
    pfm_padding_size = 4096 - (pfm_size % 4096)
    padding_data = bytearray([0xff] * pfm_padding_size)
    pfm_inst.length = pfm_size + pfm_padding_size
    full_pfm_inst = bytearray(pfm_inst) + padding_data
    signed_pfm = sign_image(xml_dict, full_pfm_inst)

    return signed_pfm

def main():
    if len(sys.argv) < 2:
        print_usage()
    xml_dict = load_xml(sys.argv[1])
    cpld_imgs, total_image_size = gen_indv_cpld_images(xml_dict)
    pfm_img = gen_pfm_image(xml_dict, cpld_imgs)
    reserved = bytearray([0xff] * 2048)
    print(total_image_size)
    unsigned_full_image = pfm_img
    unsigned_full_image += reserved
    for img in cpld_imgs:
        unsigned_full_image += img[PROP_IMAGE]

    signed_full_image = sign_image(xml_dict, unsigned_full_image)
    with open("cpld_signed_cap.bin", 'wb') as fw:
        fw.write(signed_full_image)

if __name__ == '__main__':
    main()
