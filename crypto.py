DEFAULT_PASSWORD_SALT_SIZE = 12
DEAFULT_ITERATION_COUNT = 10000

class Crypto:
    def __init__(self, password_salt_size = DEFAULT_PASSWORD_SALT_SIZE, interation_count = DEAFULT_ITERATION_COUNT):
        if type(password_salt_size) is not int:
            raise TypeError('password_salt_size must be a number')
        if type(interation_count) is not int:
            raise TypeError('iteration_count must be a number')
        self.password_salt_size = password_salt_size
        self.iteration_count = interation_count
