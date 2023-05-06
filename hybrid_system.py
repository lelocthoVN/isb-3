import logging
import json
import argparse
from generation_key import GenerationKey
from encryption import Encryption
from decryption import text_decryption

SETTINGS_FILE = 'settings.json'


def load_settings(settings_file: str) -> dict:
    """
    Считывает из файла параметры.
    :param settings_file: путь до файла с параметрами
    :return: параметры
    """
    try:
        with open(settings_file) as json_file:
            setting = json.load(json_file)
        logging.info('Настройки успешно считаны')
    except OSError as err:
        logging.warning(f'{err} ошибка при чтении из файла {settings_file}')
    return setting


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', type=str,
                        help='Использовать собственный файл с настройками (Указать путь к файлу)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action='store_true', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption',action='store_true', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption',action='store_true', help='Запускает режим дешифрования')
    args = parser.parse_args()

    if args.settings:
        settings = load_settings(args.settings)
    else:
        settings = load_settings(SETTINGS_FILE)
    if settings:
        if args.generation:
            GenerationKey(settings['symmetric_key'], settings['public_key'], settings['secret_key']).asymmetric_key()
            GenerationKey(settings['symmetric_key'], settings['public_key'],
                          settings['secret_key']).symmetric_key_encryption()
        elif args.encryption:
            Encryption(settings['symmetric_key'], settings['secret_key']).text_encryption(settings['initial_text'],
                                                                                          settings['encrypted_text'],
                                                                                          settings['iv_key'])
        else:
            text_decryption(settings['secret_key'], settings['symmetric_key'], settings['encrypted_text'],
                            settings['decrypted_text'], settings['iv_key'])
