import random
from AES import AESCipher
from charm.toolbox.pairinggroup import ZR

# step 1 
def dc_to_do(params,sk_k,qk_i):
    # sk_k - private key of DC_k
    # qk_i - public key of DO_p_i

    # Random value selection by DC
    a_k = params['group'].random(ZR)
    t_k = a_k * params['P']

    # Compute the bilinear mapping from private key , public key 
    e_result = params['e'](sk_k,qk_i)

    # Hashing operation
    hash_input = str(t_k) + str(e_result)
    sigma_k = params['H1'](hash_input)

    # This data will be sent to DO over a public channel
    return (a_k,t_k ,sigma_k)

# step 3
def do_to_dc(params,sk_i,qk_k):
    # sk_i - private key of DO_p_i
    # qk_k - public key of DC_k 

    a_i,t_i,sigma_i=dc_to_do(params,sk_i,qk_k)
    return (a_i,t_i,sigma_i)

# step 2 and 4
def correctness(params,t_k,sigma,sk_i,qk_k):
    # Compute the bilinear mapping from private key , public key 
    e_result = params['e'](sk_i,qk_k)
    hash_input = str(t_k) + str(e_result)
    hash_result = params['H1'](hash_input)
    if sigma!=hash_result:
        print('Invalid request. Terminating Session...')
        return False
    print('Successful match. Assuming legit request')
    return True

# step 5
def common_session_key(params,id_i,id_k,t_i,t_k,a_i,a_k,sigma_i):
    input1 = id_i + id_k + str(t_i) + str(t_k) + str(a_i * t_k)
    hash_result_1=params['H1'](input1)

    input2= id_i+id_k+str(t_i)+str(t_k)+str(a_k*t_i)
    hash_result_2=params['H1'](input2)

    input3=id_i+id_k+str(t_i)+str(t_k)+str(a_i*a_k*params['P'])
    hash_result_3=params['H1'](input3)

    print(f'\nSession Key 1 : {hash_result_1}')
    print(f'Session Key 2 : {hash_result_2}')
    print(f'Session Key 3 : {hash_result_3}\n')

    if str(hash_result_1)==str(hash_result_2)==str(hash_result_3):
        return hash_result_3
    return None

# step 6
def select_keyword(S_ik,keywords):
    cipher = AESCipher(str(S_ik))
    # Choose a random keyword
    w_j = random.choice(keywords)
    Esik = cipher.encrypt(w_j)
    return w_j,Esik

# step 7
def recieve_keyword(params,S_ik,Esik,sk_i):
    cipher2 = AESCipher(str(S_ik))
    decrypt_keyword = cipher2.decrypt(Esik)
    print(f'Decrypted keyword : {decrypt_keyword}')

    t_i_bar=params['group'].random(ZR)
    T1=t_i_bar*sk_i
    T2=t_i_bar*params['H0'](decrypt_keyword)
    T_wj=(T1,T2)
    return T_wj,t_i_bar, T1, T2

# step 8
def trapdoor2(params,t_i_bar,sk_i,del_i,qk_i):
    temp1 = params['e'](t_i_bar * sk_i, (t_i_bar ** -1) * params['H0'](del_i))
    # Is this H1 necessary???
    temp2 = params['H1'](params['e'](t_i_bar * qk_i,(t_i_bar ** -1) * params['H0'](del_i)))
    T_id = temp1 * temp2
    print(f'T_id : {T_id}\n')
    return T_id

# step 9
def trapdooR(params,sk_k,sk_i,qk_i,qk_k,id_i,id_k,del_i,keywords):
    a_k, t_k, sigma_k=dc_to_do(params, sk_k, qk_i)
    flag = correctness(params, t_k, sigma_k, sk_i, qk_k)
    if not flag:
        print('Flag is false ')
        return
    a_i, t_i, sigma_i = do_to_dc(params, sk_i, qk_k)
    flag = correctness(params, t_i, sigma_i, sk_k, qk_i)
    if not flag:
        print('Flag2 is false ')
        return
    S_ik = common_session_key(params, id_i, id_k, t_i, t_k, a_i, a_k, sigma_i)
    if S_ik == None :
        print('Session keys did not match')
        return
    w_j, Esik = select_keyword(S_ik, keywords)
    print(f'Keyword : {w_j}\nEncrypted and sent keyword : {Esik}')
    T_wj,t_i_bar, T1, T2=recieve_keyword(params,S_ik,Esik,sk_i)
    T_id = trapdoor2(params,t_i_bar,sk_i,del_i,qk_i)
    return T_wj,T_id,t_i_bar,w_j, S_ik, T1, T2
#=======
 #   T_w,t_i1=recieve_keyword(params,S_ik,Esik,sk_i)
 #  T_id=trapdoor2(params,t_i1,sk_i,del_i,qk_i)
 #   return T_w,T_id,t_i1,w_j,S_ik
#>>>>>>> main
