# MP Image Tool

Python tool for generating full mp binary(mcuboot + preload firmware + otp image)

## Prerequistie
1. Run west init to create workspace
   ```
   west init -m https://github.com/AspeedTech-BMC/aspeed-zephyr-project --mr aspeed-master workspace
   ```
2. Run west update in workspace folder
   ```
   west update
   ```
3. Install python modules for signing device firmware
   ```
   pip3 install imgtool
   pip3 install --user -r workspace/bootloader/mcuboot/scripts/requirements.txt
   ```
4. Download socsec in workspace
   ```
   git clone https://github.com/AspeedTech-BMC/socsec workspace/socsec
   ```
5. Setup socsec in workspace/socsec
   Refer to README.md of socsec
   ```
   sudo apt-get install python3 python3-pip python3-virtualenv
   virtualenv .venv
   source .venv/bin/activate
   pip3 install -r requirements.txt
   python3 setup.py install
   ```

## Usage
1. Modify config file to change path(optional)

2. Run python script to genrate preload binary with DICE support
   ```
   python3 mp-binary-generator.py
   ```
   or run the following script to generate preload binary without DICE support
   ```
   python3 programmer_preload_gen.py
   ```
   Result:

   ```
   workspace      : /home/aspeed-pfr/workspace
   build path     : /home/aspeed-pfr/workspace/build/
   socsec path    : /home/aspeed-pfr/workspace/socsec/
   OTP config     : /home/aspeed-pfr/workspace/aspeed-zephyr-project/apps/preload-fw/sample/otp/config/1060A1_ECDSA_MP.json
   OTP key        : /home/aspeed-pfr/workspace/aspeed-zephyr-project/apps/preload-fw/sample/otp/key
   MCUBoot key    : /home/aspeed-pfr/workspace/aspeed-zephyr-project/apps/preload-fw/sample/otp/key/rk384_prv.pem
   Preload FW key : /home/aspeed-pfr/workspace/aspeed-zephyr-project/apps/preload-fw/sample/mp/key/root-rsa-2048.pem
   ROT FW key     : /home/aspeed-pfr/workspace/aspeed-zephyr-project/apps/preload-fw/sample/mp/key/rot_image_sign.pem
   
   Image Path     : /home/aspeed-pfr/workspace/build/mp_imgs/
   
   ```
   MP binary `ast1060-mp-odm-all.bin` will be stored in Image Path

