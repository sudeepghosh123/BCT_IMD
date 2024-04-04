from AES import AESCipher
import random
from charm.toolbox.pairinggroup import ZR

# Encrypt the data
def encrypT(params,EMR, qki, qkl, skt, ski, qkt, idi, idt,del_i, keywords, idj):

    EMR = int(params['H1'](str(EMR)))
    print(f'EMR : {EMR}\n')

    # step 1
    r_t = params['group'].random(ZR)
    R_t = r_t * params['P']
    tmp_pair = str(params['e'](qki+qkl, r_t * params['P0']))
    tmp_hash = int(params['H1'](tmp_pair))
    # print(f'STR : {str(tmp_pair)}')
    print(f'TMP_HASH : {tmp_hash}, type: {type(tmp_hash)}\n')
    # print(type(EMR))
    V_t = EMR ^ tmp_hash
    # print(f'VTA : {Vt}')
    a_t = params['group'].random(ZR)
    T_t = a_t * params['P']
    tmp_pair2 = str(params['e'](skt, qki))
    sigma_t = params['H1'](str(T_t) + tmp_pair2)
    print(f'Sigma T : {sigma_t}\n')
    # It will send T_t and sigma_t to DOi
    # return {T_t, sigma_t}

    # step 2
    # Now the DOPi works on this data
    tmp_pair3 = str(params['e'](ski, qkt))
    sigmat1 = params['H1'](str(T_t) + tmp_pair3)
    if sigma_t != sigmat1:
        print(f'Invalid request. Terminating Session...\n')
        return
    print(f'Successful match. Assuming legit request\n')

    # step 3
    a_i = params['group'].random(ZR)
    T_i = a_i * params['P']
    sigma_i = params['H1'](str(T_i) + tmp_pair3)
        
    # DOi sends this data to Dt
    # return {T_i, sigma_i}

    # step 4
    # Now Dt will work on the data
    prod1 = str(a_i * T_t)
    prod2 = str(a_t * T_i)
    prod3 = str(a_i * a_t * params['P'])

    # Key with DOi
    Sit1 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod1)

    # Key with Dt
    Sit2 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod2)

    # Both keys are quivalent to this
    Sit3 = params['H1'](idi + idt + str(T_i) + str(T_t) + prod3)

    print(f'Sit1 : {Sit1}')
    print(f'Sit2 : {Sit2}')
    print(f'Sit3 : {Sit3}\n')

    # Now this data is encrypted my the Sit and sent to the DOi
    cipher = AESCipher(str(Sit1))
    # Choose a random keyword
    wi = random.choice(keywords)
    # wi = 'covid'
    Esit = cipher.encrypt(wi)
    print(f'Keyword : {wi}\nEncrypted keyword : {Esit}\n')

    # step 5
    # Now the DOi will decrypt the message with the common session key
    cipher2 = AESCipher(str(Sit2))
    decrypt_keyword = cipher2.decrypt(Esit)
    print(f'Decrypted keyword : {decrypt_keyword}\n')

    # step 6
    t_i = params['group'].random(ZR)
    C_1 = t_i * ski
    C_2 = t_i * params['H0'](decrypt_keyword)
    ti_inv = t_i ** -1
    print(f'ti : {t_i}')
    print(f'C1 : {C_1}')
    print(f'C2 : {C_2}')
    print(f'ti_inverse: {ti_inv}\n')
    
    prod4 = ti_inv * params['H0'](del_i)
    C_id = params['e'](C_1, prod4)
    C_i = (C_1, C_2)
    
    print(f'Cid : {C_id}\n')

    # Now DOi sends Esit(Ci) and Esit(Cid)
    Esit_ci = cipher2.encrypt(str(C_i))
    Esit_cid = cipher2.encrypt(str(C_id))

    print(f'Esit(ci) : {Esit_ci}\n')
    print(f'Esit(cid) : {Esit_cid}\n')

    # step 7
    # Now Dt will decrypt the data
    decrypt_ci = cipher.decrypt(Esit_ci)
    
    print(f'Ci : {C_i}\n')
    print(f'Decrypt Ci : {decrypt_ci}\n')
    if str(C_i)==str(decrypt_ci):
        print("decrypted_ci and C_i matched")

    C_3 = params['e'](qkl, r_t*params['P0'])
    A_i = (r_t * params['H1'](skt + params['H0'](wi)) * params['P1']) + (r_t * params['H0'](wi) * params['P'])
    exp = r_t * params['H1'](skt + params['H0'](wi))
    J_i = params['e'](params['P'], params['P1']) ** exp
    X_bar_i = []
    for i in range(1, len(keywords)+1):
        temp = r_t * ((params['H0'](wi)) ** i) * params['P']
        X_bar_i.append(temp)
    
    C_wi = (C_i, C_3)
    C_2_i = (A_i, J_i, X_bar_i)

    print(f'C3 : {C_3}\n')
    print(f'Ai : {A_i}\n')
    print(f'exp : {exp}\n')
    print(f'X_bar_i : {X_bar_i}\n')
    print(f'Ji : {J_i}\n')

    # Consensus protocol for private blockchain
    u_s = params['H1'](str(del_i))

    # Dt selects rt_bar
    rt_bar = params['group'].random(ZR)
    T_del_i = (rt_bar ** -1) * params['H0'](del_i)

    sigma_del_i = params['e'](rt_bar * qki, T_del_i)
    pid_i = (T_del_i, sigma_del_i, idj)

    # Dt also computes
    alpha_t = rt_bar * params['H0'](skt)
    gamma_t = (rt_bar ** -1) * params['H0'](skt * del_i)
    del_i_dash = params['e'](params['H0'](skt), params['H0'](skt * del_i))
    del_i_dash = int(params['H1'](del_i_dash)) ^ int(params['H1'](del_i))

    print(f'alpha_t : {alpha_t}\n')
    print(f'gamma_t : {gamma_t}\n')
    print(f'del_i_dash : {del_i_dash}\n')

    # This is sent to the blockchain as proof of consensus
    n_t = (alpha_t, gamma_t, del_i_dash)
    # The verifier has idj and n_t and searches for u_s in Local server
    del_t_star = int(params['H1'](params['e'](alpha_t, gamma_t))) ^ int(del_i_dash)
    lhs = del_t_star
    rhs = u_s

    # Going back steps
    # step0 = del_t_star
    # step1 = params['H1'](str(del_i))
    # step2_1 = params['H1'](params['e'](params['H0'](str(skt)), params['H0'](skt * del_i)))
    # step2_2 = params['H1'](params['e'](params['H0'](str(skt)), params['H0'](skt * del_i)))
    # step2_3 = params['H1'](del_i)
    # step2 = int(step2_1) ^ int(step2_2) ^ int(step2_3)

    # # step3_1 = params['H1'](params['e'](params['H0'](skt)))
    # step3_1 = params['H1'](params['e'](params['H0'](str(skt)), params['H0']((skt * del_i) ** (r_t * (r_t**-1)))))
    # step3_2 = params['H1'](params['e'](params['H0'](str(skt)), params['H0'](skt * del_i)))
    # step3_3 = params['H1'](del_i)
    # step3 = int(step3_1) ^ int(step3_2) ^ int(step3_3)

    # step4_1 = params['H1'](params['e'](alpha_t, gamma_t))
    # step4_2 = del_i_dash
    # step4 = int(step4_1) ^ int(step4_2)


    print(f'del_t_star : {lhs}\n')
    print(f'u_s : {rhs}\n')
    # print(f'step0 : {step0}\n')
    # print(f'step1 : {step1}\n')
    # print(f'step2 : {step2}\n')
    # print(f'step3 : {step3}\n')
    # print(f'step4 : {step4}\n')

    if int(del_t_star) == int(u_s):
        print('------------------------------------------')
        print('Private Blockchain Consensus match')
        print('------------------------------------------\n')
    else:
        print('------------------------------------------')
        print('Private Blockchain Consensus failed')
        print('------------------------------------------\n')

    # Consensus protocol for consortium blockchain
    T_xi = (idj, pid_i, C_wi)
    # Broadcast data
    broadcast = (T_xi, C_2_i, C_id)
    A_i, J_i, X_bar_i = C_2_i

    print(f'A_i {A_i}\n')
    print(f'J_i {J_i}\n')
    print(f'X_bar_i {X_bar_i}\n')

    lhs = params['e'](A_i, params['P'])
    rhs = params['e'](params['P'], X_bar_i[0]) * J_i
    print(f'LHS : {lhs}\n')
    print(f'RHS : {rhs}\n')

    if str(lhs) == str(rhs):
        print('------------------------------------------')
        print('Consortium consensus Matches successfully')
        print('------------------------------------------\n')
    else:
        print('------------------------------------------')
        print('Consortium Consensus failed')
        print('------------------------------------------\n')

    return wi,R_t,V_t,C_3,C_id,t_i, C_1, C_2, sigma_del_i, C_wi
