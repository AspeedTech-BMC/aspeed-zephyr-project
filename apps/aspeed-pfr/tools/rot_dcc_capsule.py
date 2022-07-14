#!/usr/bin/python3
# script to create ROT Decommission Capsule

import sys
import os
import argparse
import logging
import subprocess
import shutil
import pathlib

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def main(args):
    """ main program
    :param -t input_sign_tool
    :param -c xml configure file, default is rot_dcc_capsule.xml
    :param -o output image, default is rot_dcc_capsule_signed.bin
    """
    parser = argparse.ArgumentParser(description='create ROT dcc capsule')
    parser.add_argument('-t',
                        '--input_sign_tool',
                        required=True,
                        metavar="[input sign tool]",
                        dest='input_sign_tool',
                        help='sign tool')
    parser.add_argument('-c',
                        '--input_xml',
                        metavar="[input xml]",
                        dest='input_xml',
                        default='rot_dcc_capsule.xml',
                        help='xml configure file,\
                        default is rot_dcc_capsule.xml')
    parser.add_argument('-o',
                        '--out_img',
                        metavar="[output image]",
                        dest='out_img',
                        default='rot_dcc_capsule_signed.bin',
                        help='output image,\
                        default is rot_dcc_capsule_signed.bin')
    args = parser.parse_args(args)
    logger.info(args)

    logger.info("create decommission payload")
    payload = 'dcc_payload.bin'

    with open(payload, 'wb') as fd:
        fd.write(b'\x00'*128)

    logger.info("sign %s", payload)
    cmd = "{} -c {} -o {} {} -v".format(args.input_sign_tool,
                                        args.input_xml,
                                        args.out_img,
                                        payload)
    logger.info("issue: %s", cmd)
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    logger.info(out.decode("utf-8"))

    if (p.returncode):
        logger.error(err.decode("utf-8"))
        exit(1)

    work_path = pathlib.Path(__file__).parent.absolute()
    output_path = os.path.join(work_path, 'dss-output')
    logger.info('work_path: %s', work_path)
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    pathlib.Path(output_path).mkdir(parents=True, exist_ok=True)
    shutil.move(args.out_img, output_path)
    shutil.move(payload, output_path)
    shutil.move(payload + "_aligned", output_path)
    logger.info('ROT decommission capsule in: %s', output_path)


if __name__ == '__main__':
    main(sys.argv[1:])
