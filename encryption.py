import logging
import os
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger()
logger.setLevel('INFO')


class Encryption:
    def __init__(self, symmetric_key_path: str, private_key_path: str) -> None:
        """
        :param private_key_path: путь до закрытого ключа
        :param symmetric_key_path: путь до симметричного ключа
        """
        self.symmetric_key_path = symmetric_key_path
        self.private_key_path = private_key_path

    def decryption_of_symmetric_key(self) -> bytes:
        """
        Считывает из файла зашифрованный симметричный ключ и дешифрует его Parameters
        """
        try:
            with open(self.symmetric_key_path, mode="rb") as f:
                en_key = f.read()
            logging.info('Симметричный ключ успешно прочитан')
        except OSError as err:
            logging.warning(f'{err} ошибка чтении из файла {self.symmetric_key_path}')
        try:
            with open(self.private_key_path, 'rb') as pem_in:
                private_key = pem_in.read()
            logging.info('Закрытый ключ успешно прочитан')
        except OSError as err:
            logging.warning(f'{err} ошибка чтении из файла {self.private_key_path}')
        d_private_key = load_pem_private_key(private_key, password=None)
        dc_key = d_private_key.decrypt(en_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(), label=None))
        return dc_key

    def text_encryption(self, initial_text_path: str, encrypt_text_path: str, iv_path: str) -> None:
        """
        Считывает текст из файла, шифрует его и сохраняет результат в файл по указанному пути

        :param initial_text_path: путь до исходного текста
        :param encrypt_text_path: путь до зашифрованного текста
        :param iv_path: путь для сохранения векторa блочного режимв
        :return: None
        """
        key = self.decryption_of_symmetric_key()
        try:
            with open(initial_text_path, 'r', encoding='utf-8') as f:
                text = f.read()
            logging.info('Исходный текст прочитан')
        except OSError as err:
            logging.warning(f'{err} ошибка чтении из файла {initial_text_path}')
        padder = sym_padding.ANSIX923(128).padder()
        padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
        iv = os.urandom(16)
        try:
            with open(iv_path, 'wb') as key_file:
                key_file.write(iv)
            logging.info('Вектор блочного режимв создан')
        except OSError as err:
            logging.warning(f'{err} ошибка чтении из файла {iv_path}')
        cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_text) + encryptor.finalize()
        try:
            with open(encrypt_text_path, 'wb') as f_text:
                f_text.write(c_text)
            logging.info('Текст зашифрован и записан в файл')
        except OSError as err:
            logging.warning(f'{err} ошибка записи в файл{encrypt_text_path}')
