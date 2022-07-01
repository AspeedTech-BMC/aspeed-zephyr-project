#!/usr/bin/python3
# script to create key cancellation capsule

import sys
import os
import argparse
import logging
import subprocess
import shutil
import pathlib
import struct

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def main(args):
    """ main program
    :param -t input_sign_tool
    :param -c xml configure file, default is kcc_capsule.xml
    :param -o output image, default is kcc_csk(id)_cap_signed.bin
    """
    parser = argparse.ArgumentParser(description='create kcc capsule')
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
                        default='kcc_capsule.xml',
                        help='xml configure file,\
                        default is kcc_capsule.xml')
    parser.add_argument('-o',
                        '--out_img',
                        metavar="[output image]",
                        dest='out_img',
                        default=None,
                        help='output image,\
                        default is kcc_csk(id)_cap_signed.bin')
    parser.add_argument('-k',
                        '--csk_id',
                        metavar="[csk id]",
                        dest='csk_id',
                        default='0',
                        type=int,
                        choices=range(0, 128),
                        help='key cancellation CSK id (0-127),\
                        default is 0')
    args = parser.parse_args(args)
    logger.info(args)

    logger.info("create key cancellation payload")
    payload = 'kcc_csk{}_payload.bin'.format(args.csk_id)
    outimg = args.out_img

    if outimg is None:
        outimg = 'kcc_csk{}_cap_signed.bin'.format(args.csk_id)

    with open(payload, 'wb') as fd:
        fd.write(struct.pack('I', args.csk_id))
        fd.write(b'\x00'*124)

    logger.info("sign %s", payload)
    cmd = "{} -c {} -o {} {} -v".format(args.input_sign_tool,
                                        args.input_xml,
                                        outimg,
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
    output_path = os.path.join(work_path, 'kcc-output')
    logger.info('work_path: %s', work_path)
    if os.path.exists(output_path):
        shutil.rmtree(output_path)
    pathlib.Path(output_path).mkdir(parents=True, exist_ok=True)
    shutil.move(outimg, output_path)
    shutil.move(payload, output_path)
    shutil.move(payload + "_aligned", output_path)
    logger.info('key cancellation capsule in: %s', output_path)


if __name__ == '__main__':
    main(sys.argv[1:])
