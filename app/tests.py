import pytest
from .lib.security import htmlspecialchars, check_code

# ***********************************************************
# ******************** TEST DE SECURITE ********** **********
# ***********************************************************


def test__malicious_code_replacement():

    text = ">test"
    assert text != htmlspecialchars(text)


def test_legit_string():

    text = "test"
    assert text == htmlspecialchars(text)


def test_data_received_with_malicious_code():

    data = [{
        'test': 'test',
        'test': '<test',
        'test': 'test'
    }]

    with pytest.raises(Exception):
        check_code(data)