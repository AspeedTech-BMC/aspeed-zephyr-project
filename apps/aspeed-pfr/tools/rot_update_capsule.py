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
    :param -t input_sign_tool
    :param -c
    :param -i input image
    :param -o output image, default is rot_signed.bin
    """
    parser = argparse.ArgumentParser(description='sign ROT update capsule')
    parser.add_argument('-t',
                        '--input_sign_tool',
                        metavar="[input sign tool]",
                        dest='input_sign_tool',
                        default=None,
                        help='sign tool')
    parser.add_argument('-c',
                        '--input_xml',
                        metavar="[input xml]",
                        dest='input_xml',
                        default=None,
                        help='xml configure file')
    parser.add_argument('-i',
                        '--input_img',
                        metavar="[input image]",
                        dest='input_img',
                        default=None,
                        help='raw image to be signed')
    parser.add_argument('-o',
                        '--out_img',
                        metavar="[output image]",
                        dest='out_img',
                        default='rot_signed.bin',
                        help='output image')
    args = parser.parse_args(args)
    logger.info(args)

    if args.input_sign_tool is None:
        logger.error("please set sign tool")
        exit(1)
    if args.input_xml is None:
        logger.error("please set input xml")
        exit(1)
    if args.input_img is None:
        logger.error("please set input image")
        exit(1)

    logger.info("sign ROT update capsule")
    cmd = "{} -c {} -o {} {}".format(args.input_sign_tool,
                                     args.input_xml,
                                     args.out_img,
                                     args.input_img)
    logger.info("issue: %s", cmd)
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()

    if (p.returncode):
        logger.error(err)
        logger.error("create ROT update capsule failed")
        exit(1)

    work_path = pathlib.Path(__file__).parent.absolute()
    output_path = os.path.join(work_path, 'output')
    logger.info('work_path: %s', work_path)
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    pathlib.Path(output_path).mkdir(parents=True, exist_ok=True)
    shutil.move(args.out_img, output_path)
    shutil.move(args.input_img + "_aligned", output_path)


if __name__ == '__main__':
    main(sys.argv[1:])
