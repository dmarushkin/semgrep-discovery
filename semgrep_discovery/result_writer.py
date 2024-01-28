import logging
import json
from pathlib import Path
from dataclasses import asdict


class ResultWriter:
    def __init__(self, outfile: str, format: str):
        self.outfile = Path(outfile)
        self.format = format
        self.logger = logging.getLogger(__name__)

    def write_results_to_file(self, objects):

        if self.format == 'json' :
            with open(self.outfile, 'w') as f:
                for row in objects:
                    f.write(json.dumps(asdict(row), ensure_ascii=False))  # noqa
                    f.write('\n')

            self.logger.info(f"{len(objects)} written to {self.outfile}")
