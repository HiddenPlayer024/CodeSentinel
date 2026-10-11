import pytest
import yaml

def test_yaml_import_and_parse():
    content = "test: 123"
    result = yaml.safe_load(content)
    assert result == {"test": 123}
