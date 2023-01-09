import os
import sys
import configparser

config = configparser.ConfigParser()
config.read('mp_build_env.conf')
workspace_path = config['PATH'].get('WorkspacePath', "../../../../")
workspace_path = os.path.abspath(workspace_path)
sample_path = workspace_path + '/aspeed-zephyr-project/apps/preload-fw/sample'

build_path = config['PATH'].get('BuildPath', workspace_path + '/build/')
socsec_path = config['PATH'].get('SocsecPath', workspace_path + '/socsec/')
mp_imgs_path = config['PATH'].get('MPImagePath', build_path + 'mp_imgs/')
otp_cfg = config['PATH'].get('OTPConfig', sample_path + '/otp/config/1060A1_ECDSA_MP.json')
otp_key_path = config['PATH'].get('OTPKeyPath', sample_path + '/otp/key')

mcuboot_key = config['KEY'].get('MCUBootKey', sample_path + '/otp/key/rk384_prv.pem')
preload_fw_key = config['KEY'].get('PreloadFWKey', sample_path + '/mp/key/root-rsa-2048.pem')
rot_fw_key = config['KEY'].get('RoTFWKey', sample_path + '/mp/key/rot_image_sign.pem')

pristine = config['BUILD_OPTION'].get('Pristine', 'always')

def gen_mcuboot_img():
    cmd = 'cd ' + workspace_path + ';source zephyr/zephyr-env.sh;' + \
            ' west build -b ast1060_dcscm_dice' + \
            ' -d ' + build_path + 'mcuboot' + \
            ' bootloader/mcuboot/boot/zephyr/' + \
            ' -p ' + pristine + \
            ' -DDTC_OVERLAY_FILE="$ZEPHYR_BASE/' + \
            '../bootloader/mcuboot/boot/zephyr/boards/ast1060_dcscm_dice.overlay"' + \
            ' -DCMAKE_EXPORT_COMPILE_COMMANDS=1'
    os.system(cmd)
    return

def sign_mcuboot():
    unsigned_mcuboot = build_path + 'mcuboot/zephyr/zephyr.bin'
    cmd = 'mkdir -p ' + mp_imgs_path + \
            ';cd ' + socsec_path + \
            ';socsec make_secure_bl1_image --soc 1060 --algorithm ECDSA384 --bl1_image ' + \
            unsigned_mcuboot + \
            ' --output ' + mp_imgs_path + 'mcuboot.signed.bin' + \
            ' --ecdsa_sign_key ' + mcuboot_key
    os.system(cmd)
    return

def gen_preload_fw():
    cmd = 'cd ' + workspace_path + \
            '; west build -b ast1060_dcscm_dice' + \
            ' -d ' + build_path + 'preload' + \
            ' aspeed-zephyr-project/apps/preload-fw' + \
            ' -p ' + pristine
    os.system(cmd)
    return

def sign_preload_fw():
    unsigned_preload_fw = build_path + 'preload/zephyr/zephyr.bin'
    cmd = 'imgtool sign --version 1.7.1 --align 8 --header-size 1024 --slot-size 393216' + \
            ' --load-addr 196608 --key ' + preload_fw_key + \
            ' ' + unsigned_preload_fw + \
            ' ' + mp_imgs_path + 'preload.signed.bin'
    os.system(cmd)
    return

def gen_rot_fw():
    cmd = 'cd ' + workspace_path + \
            '; west build -b ast1060_dcscm_dice' + \
            ' -d ' + build_path + 'rot' + \
            ' aspeed-zephyr-project/apps/aspeed-pfr' + \
            ' -p ' + pristine
    os.system(cmd)
    return

def sign_rot_fw():
    unsigned_rot_fw = build_path + 'rot/zephyr/zephyr.bin'
    cmd = 'imgtool sign --version 1.7.1 --align 8 --header-size 1024 --slot-size 393216' + \
            ' --load-addr 196608 --key ' + rot_fw_key + \
            ' ' + unsigned_rot_fw + \
            ' ' + mp_imgs_path + 'rot.signed.bin'
    os.system(cmd)
    return

def gen_otp_img():
    cmd = 'otptool make_otp_image ' + otp_cfg +' --no_last_bit' + \
    ' --key_folder ' + otp_key_path + \
    ' --output_folder ' + mp_imgs_path
    os.system(cmd)
    return

def gen_preload_bin():
    signed_mcuboot = mp_imgs_path + 'mcuboot.signed.bin'
    signed_preload = mp_imgs_path + 'preload.signed.bin'
    otp_img = mp_imgs_path + 'otp-all.image'
    mp_final_img = mp_imgs_path + 'ast1060-mp-all.bin'

    with open(signed_mcuboot, 'rb') as mbf:
        mcuboot_content = mbf.read()

    with open(signed_preload, 'rb') as plf:
        preload_content = plf.read()

    with open(otp_img, 'rb') as otf:
        otp_content = otf.read()

    with open(mp_final_img, 'wb') as f:
        f.write(b'\xff' * 1024 * 1024)
        f.seek(0)
        f.write(mcuboot_content)
        f.seek(0x20000)
        f.write(preload_content)
        f.seek(0x80000)
        f.write(preload_content)
        f.seek(0xe0000)
        f.write(otp_content)

    return

def gen_preload_bin_odm():
    signed_mcuboot = mp_imgs_path + 'mcuboot.signed.bin'
    signed_preload = mp_imgs_path + 'preload.signed.bin'
    signed_rot = mp_imgs_path + 'rot.signed.bin'
    otp_img = mp_imgs_path + 'otp-all.image'
    mp_final_img = mp_imgs_path + 'ast1060-mp-odm-all.bin'

    with open(signed_mcuboot, 'rb') as mbf:
        mcuboot_content = mbf.read()

    with open(signed_preload, 'rb') as plf:
        preload_content = plf.read()

    with open(signed_rot, 'rb') as srf:
        rot_content = srf.read()

    with open(otp_img, 'rb') as otf:
        otp_content = otf.read()

    with open(mp_final_img, 'wb') as f:
        f.write(b'\xff' * 1024 * 1024)
        f.seek(0)
        f.write(mcuboot_content)
        f.seek(0x20000)
        f.write(preload_content)
        f.seek(0x80000)
        f.write(rot_content)
        f.seek(0xe0000)
        f.write(otp_content)

    return

cmd = 'rm -rf ' + mp_imgs_path
os.system(cmd)
cmd = 'mkdir -p ' + mp_imgs_path
os.system(cmd)

gen_otp_img()
gen_mcuboot_img()
sign_mcuboot()

gen_preload_fw()
sign_preload_fw()
gen_preload_bin()

# Customer's firmware
gen_rot_fw()
sign_rot_fw()
gen_preload_bin_odm()


print("workspace      : " + workspace_path)
print("build path     : " + build_path)
print("socsec path    : " + socsec_path)
print("OTP config     : " + otp_cfg)
print("OTP key        : " + otp_key_path)
print("MCUBoot key    : " + mcuboot_key)
print("Preload FW key : " + preload_fw_key)
print("ROT FW key     : " + rot_fw_key)
print("\nImage Path     : " + mp_imgs_path + "\n")
