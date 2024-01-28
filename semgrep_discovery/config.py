import argparse
from collections.abc import Sequence
from typing import Optional, List
from pydantic import BaseModel


class ConfigModel(BaseModel):

    workdir: str
    langs: List[str]
    objects: List[str]
    keywords: List[str]
    outfile: Optional[str]
    format: Optional[str]


def config_from_args(args: Optional[Sequence[str]] = None) -> ConfigModel:

    argparser = argparse.ArgumentParser(
        prog="semgrep-discovery",
        description="Discovery sensitive objects in code",
    )

    argparser.add_argument('--wd', type=str, help='Project work directory to scan', required=True)
    argparser.add_argument('--langs', type=str, help='Languages to scan', required=True)
    argparser.add_argument('--objects', type=str, help='Objects to search', required=True)
    argparser.add_argument('--keywords', type=str, help='Sencitive keywords in objects', required=True)
    argparser.add_argument('--outfile', type=str, help='Output file', required=False)
    argparser.add_argument('--format', type=str, help='Output format', required=False)

    args = argparser.parse_args()

    config_obj = ConfigModel(
        workdir=args.wd,
        langs=args.langs.split(','),
        objects=args.objects.split(','),
        keywords=args.keywords.split(','),
    )

    if args.outfile:
        config_obj.outfile = args.outfile

    if args.format:
        config_obj.format=args.format

    return config_obj
