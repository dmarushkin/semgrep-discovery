import logging

from .config import config_from_args
from .semgrep_runner import SemgrepRunner
from .result_writer import ResultWriter


def main():

    config = config_from_args()

    logging.basicConfig(
        format='%(message)s',
        level=logging.getLevelName("INFO"),
    )

    semgrep_runner = SemgrepRunner(
        workdir=config.workdir,
        langs=config.langs,
        objects=config.objects,
        keywords=config.keywords,
    )

    result_objects = semgrep_runner.find_objects()

    if config.outfile:
        res_writer = ResultWriter(outfile=config.outfile, format=config.format)
        res_writer.write_results_to_file(result_objects)

if __name__ == "__main__":
    main()