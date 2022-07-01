#!/usr/bin/python3
# python script to update ROT unsigned capsule
# and sign it with XML configure file

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
    :param -t input sign tool
    :param -c input xml configure file, default is rot_update_capsule.xml
    :param -i input image
    :param -o output image, default is rot_update_capsule_signed.bin
    """
    parser = argparse.ArgumentParser(description='sign ROT update capsule')
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
                        default='rot_update_capsule.xml',
                        help='xml configure file,\
                        default is rot_update_capsule.xml')
    parser.add_argument('-i',
                        '--input_img',
                        required=True,
                        metavar="[input image]",
                        dest='input_img',
                        help='raw image to be signed')
    parser.add_argument('-o',
                        '--out_img',
                        metavar="[output image]",
                        dest='out_img',
                        default='rot_update_capsule_signed.bin',
                        help='output image,\
                        default is rot_update_capsule_signed.bin')
    args = parser.parse_args(args)
    logger.info(args)

    logger.info("sign %s", args.input_img)
    cmd = "{} -c {} -o {} {} -v".format(args.input_sign_tool,
                                        args.input_xml,
                                        args.out_img,
                                        args.input_img)
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
    output_path = os.path.join(work_path, 'update-output')
    logger.info('work_path: %s', work_path)
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    pathlib.Path(output_path).mkdir(parents=True, exist_ok=True)
    shutil.move(args.out_img, output_path)
    shutil.move(args.input_img + "_aligned", output_path)
    logger.info('ROT update capsule in: %s', output_path)


if __name__ == '__main__':
    main(sys.argv[1:])
