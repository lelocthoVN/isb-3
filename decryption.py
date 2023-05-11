import logging
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from encryption import Encryption

logger = logging.getLogger()
logger.setLevel('INFO')


def text_decryption(private_key_path: str, symmetric_key_path: str,
                    encrypt_file_path: str, decrypt_file_path: str, iv_path: str) -> None:
    """
    Считывает из файла зашифрованный текст, дешифрует его и сохраняет результат в файл по указанному пути.
    :param private_key_path: путь до закрытого ключа
    :param symmetric_key_path: путь до симметричного ключа
    :param encrypt_file_path: путь до зашифрованного текста
    :param decrypt_file_path: путь до расщифрованного текста
    :param iv_path: инициализационный вектор блочного режимв
    :return: None
    """

    try:
        with open(encrypt_file_path, 'rb') as f:
            en_text = f.read()
        logging.info('Зашифрованный текст прочитан')
    except OSError as err:
        logging.warning(f'{err} ошибка чтении из файла {encrypt_file_path}')
    try:
        with open(iv_path, "rb") as f:
            iv = f.read()
        logging.info('Вектор был создан')
    except OSError as err:
        logging.warning(f'{err} ошибка чтении из файла {iv_path}')

    key = Encryption(private_key_path, symmetric_key_path).decryption_of_symmetric_key()
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    unpadder = sym_padding.ANSIX923(128).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    try:
        with open(decrypt_file_path, 'wb') as f:
            f.write(unpadded_dc_text)
        logging.info('Текст расшифрован и записан в файл')
    except OSError as err:
        logging.warning(f'{err} ошибка записи в файл {decrypt_file_path}')
