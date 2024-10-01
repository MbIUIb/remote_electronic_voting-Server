class JsonKeys:
    REQUEST = "request"

    KEY_EXCHANGE = "key_exchange"
    KEYEX_CLIENT_PUB_N = "client_pubkey_n"
    KEYEX_CLIENT_PUB_E = "client_pubkey_e"
    KEYEX_SERVER_PUB_N = "server_pubkey_n"
    KEYEX_SERVER_PUB_E = "server_pubkey_e"

    BLIND_SIGN_KEY_EXCHANGE = "blind_sign_key_exchange"
    BLIND_SIGN_KEYEX_CLIENT_PUB_N = "blind_sign_client_pubkey_n"
    BLIND_SIGN_KEYEX_CLIENT_PUB_E = "blind_sign_client_pubkey_e"
    BLIND_SIGN_KEYEX_SERVER_PUB_N = "blind_sign_server_pubkey_n"
    BLIND_SIGN_KEYEX_SERVER_PUB_E = "blind_sign_server_pubkey_e"

    REGISTRATION = "registration"
    REG_STATE = "reg_state"

    AUTENTICATION = "authentication"
    AUTH_STATE = "auth_state"

    CRYPT_STAGE_1_INIT = "CRYPT_STAGE_1_INIT"
    CRYPT_STAGE_1_RESPONSE = "CRYPT_STAGE_1_RESPONSE"

    BLIND_SIGN = "blind_sign"
    BLIND_MASK_IDEN_NUM = "blind_mask_iden_num"
    BLIND_SIGN_RESPONSE = "blind_sign_response"
    BLIND_SIGN_MASK_IDEN_NUM = "blind_sign_mask_iden_num"

    VOTER_ID = "id"
    IDEN_NUM_LEN = "iden_num_len"
    FIRSTNAME = "firstname"
    LASTNAME = "lastname"
    PASSWORD = "password"
    EXISTS = "exists"
    SUCCESSFUL = "successful"
    FAILED = "failed"

    JSON_HEADERS = {"Content-type": "application/json", "Accept": "text/plain"}
