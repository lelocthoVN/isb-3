import logging
import json

settings = {
    'initial_text': 'files/initial_text.txt',
    'encrypted_text': 'files/encrypted_text.txt',
    'decrypted_text': 'files/decrypted_text.txt',
    'symmetric_key': 'files/symmetric_key.txt',
    'public_key': 'files/public_key.pem',
    'secret_key': 'files/secret_key.pem',
    'iv_key': 'files/iv.bin'
}


def record_settings(settings_file: str, settings: dict) -> None:
    """
    Записывает в файл параметры.
    Parameters
    ----------
        settings_file (str):  путь до файла с параметрами
        settings (dict): параметры
    """
    try:
        with open(settings_file, 'w') as fp:
            json.dump(settings, fp)
        logging.info('Настройки успешно записаны')
    except OSError as err:
        logging.warning(f'{err} ошибка при записи в файл {settings_file}')


if __name__ == "__main__":
    record_settings('settings.json', settings)