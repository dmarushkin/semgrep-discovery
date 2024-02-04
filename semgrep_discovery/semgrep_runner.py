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
    lang: str
    object_type: str
    rule_id: str
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

        objects_dict = {}
        
        for lang in self.langs:

            for object_type in self.objects:

                rule_file = Path(self.rulesdir, lang, object_type + '.yaml')

                if rule_file.is_file():

                    self.logger.info(f'Run scan {self.workdir} with rule {rule_file}')

                    result = subprocess.run(
                        ["semgrep", "scan", "--config", rule_file, self.workdir, "--json", "--metrics=off"],
                        capture_output=True,
                        text=True
                    )

                    if result.returncode != 0:
                        self.logger.error("Semgrep encountered an error:")
                        self.logger.error(result.stderr)
                        return objects

                    semgrep_data = json.loads(result.stdout)

                    for finding in semgrep_data['results']:
                        
                        full_path = finding.get('path')

                        path = full_path[self.workdir_len + 1:]

                        rule_id = finding.get('check_id',"").split('.')[-1]

                        object = finding.get('extra').get('metavars').get('$OBJECT', {}).get('abstract_content',"")
                        field = finding.get('extra').get('metavars').get('$FIELD', {}).get('abstract_content',"")
                        line = finding.get('extra').get('metavars').get('$OBJECT').get('start').get('line')

                        uniq_obj_key = f"{path}.{object}"

                        if uniq_obj_key not in objects_dict:
                            objects_dict[uniq_obj_key] = SearchObject(
                                path=path,
                                line=line,
                                lang=lang,
                                object_type=object_type,
                                rule_id=rule_id,
                                object=object,
                                fields=[],
                                sensitive=False,
                            )
                            
                        if field and field not in objects_dict[uniq_obj_key].fields:
                            objects_dict[uniq_obj_key].fields.append(field)

                        for kw in self.keywords:
                            if kw in str(object).lower() or kw in str(field).lower():
                                objects_dict[uniq_obj_key].sensitive = True
        
        objects_type_dict = {}

        for obj in objects_dict.values():

            obj_type_key = f"{obj.lang}.{obj.object_type}.{obj.rule_id}"

            if obj_type_key not in objects_type_dict:
                objects_type_dict[obj_type_key] = []

            objects_type_dict[obj_type_key].append(obj)

            objects.append(obj)

        
        for obj_type, obj_type_array in objects_type_dict.items():
            
            self.logger.info(f"    [ { obj_type } ]")

            for obj in obj_type_array:

                self.logger.info(f"        { obj.object }")
                self.logger.info(f"            fields:    { str(obj.fields) }")
                self.logger.info(f"            path:      { obj.path }:{ obj.line }")
                if obj.sensitive:
                    self.logger.info(f"            sensitive!!!")

        self.logger.info(f"Got {len(objects)} objects")

        return objects
