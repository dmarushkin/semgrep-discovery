import logging
from typing import List
from dataclasses import dataclass
from pathlib import Path

import os

import subprocess
import json


@dataclass
class SearchObject:
    path: str
    line: int
    object_type: str
    object: str
    fields: List[str]
    sensitive: bool


class SemgrepRunner:

    def __init__(self, workdir: str, langs: List[str], objects: List[str], keywords: List[str]):

        self.workdir = Path(workdir).resolve()
        self.workdir_len = len(str(self.workdir))
        self.keywords = keywords
        self.langs = langs
        self.objects = objects

        self.rulesdir = os.path.abspath(os.path.dirname(__file__)) + '/rules'

        self.logger = logging.getLogger(__name__)
        

    def find_objects(self) -> List[SearchObject]:

        self.logger.info(f'Starting scan....')
        self.logger.info(f'     workdir: {str(self.workdir)}')
        self.logger.info(f'     langs: {str(self.langs)}')
        self.logger.info(f'     objects: {str(self.objects)}')
        self.logger.info(f'     keywords: {str(self.keywords)}')
        self.logger.info(f'     ruledir: {str(self.rulesdir)}')

        objects = []

        rules_list = []

        for lang in self.langs:
            for obj in self.objects:

                rule_file = Path(self.rulesdir, lang, obj + '.yaml')

                if rule_file.is_file():
                    rules_list.append(str(rule_file))
                    self.logger.info(f'Add rule {str(rule_file)} for scan')
                else:
                    self.logger.info(f'No rule file for {str(rule_file)}')

        for rule in rules_list:

            self.logger.info(f'Run scan {self.workdir} with rule {rule}')

            result = subprocess.run(
                ["semgrep", "scan", "--config", rule, self.workdir, "--json", "--metrics=off"],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                self.logger.error("Semgrep encountered an error:")
                self.logger.error(result.stderr)
                return objects

            semgrep_data = json.loads(result.stdout)

            objects_dict = {}

            for finding in semgrep_data['results']:
                
                full_path = finding.get('path')
                path = full_path[self.workdir_len + 1:]

                full_rule = finding.get('check_id')
                object_type = full_rule[6:]

                object = finding.get('extra').get('metavars').get('$OBJECT').get('abstract_content')
                field = finding.get('extra').get('metavars').get('$FIELD', {}).get('abstract_content')
                method = finding.get('extra').get('metavars').get('$METHOD', {}).get('abstract_content')
                line = finding.get('extra').get('metavars').get('$OBJECT').get('start').get('line')

                if path not in objects_dict:
                    self.logger.info(path)
                    objects_dict[path] = {}

                if object not in objects_dict[path]:
                    self.logger.info('   ' + object)
                    objects_dict[path][object] = { 'object_type': object_type,
                                                   'line': line,
                                                   'sensitive': False,
                                                   'fields': []}
                    
                if field and field not in objects_dict[path][object]['fields']:
                    self.logger.info('        ' + field)
                    objects_dict[path][object]['fields'].append(field)

                if method and method not in objects_dict[path][object]['fields']:
                    self.logger.info('        ' + field)
                    objects_dict[path][object]['fields'].append(method)

                for kw in self.keywords:
                    if kw in str(object).lower() or kw in str(field).lower():
                        objects_dict[path][object]['sensitive'] = True

            for path_key, path_dict in objects_dict.items():
                for object_key, object_data in path_dict.items():
                    objects.append(
                        SearchObject(
                            path=path_key,
                            line=object_data['line'],
                            object_type=object_data['object_type'],
                            object=object_key,
                            fields=object_data['fields'],
                            sensitive=object_data['sensitive'],
                        )
                    )

        self.logger.info(f"Got {len(objects)} objects")

        return objects
