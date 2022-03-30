import feature_extraction
import pandas as pd
from tkinter import *
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegressionCV
from sklearn.metrics import confusion_matrix, classification_report, plot_confusion_matrix, plot_precision_recall_curve
import threading
import imaplib
import re
import time
import email


def get_url(string):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    return [x[0] for x in url]


def connect(mail, password):
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(mail, password)
    return imap


def disconnect(imap):
    imap.logout()


def parse_uid(data):
    pattern_uid = re.compile(r'\d+ \(UID (?P<uid>\d+)\)')
    match = pattern_uid.match(data.decode('utf-8'))
    return match.group('uid')


def is_it_junk(body):
    urls = get_url(body)
    if len(urls) > 0:
        for url in urls:
            df = check_input(url)
            sc = scaler.transform(df)
            res = log_model.predict(sc)
            if res.max() == 1:
                return 1

    return 0


def move_mail(imap, msg_uid, dest):
    result = imap.uid('COPY', msg_uid, dest)
    if result[0] == 'OK':
        imap.uid('STORE', msg_uid, '+FLAGS', '(\Deleted)')
        imap.expunge()
    print("Mail carried to {} folder".format(dest))


def check_past(imap, source, dest):
    status, messages = imap.select(mailbox=source, readonly=False)
    resp, items = imap.search(None, 'All')
    email_ids = items[0].split()
    latest_email_id = email_ids[-1]

    resp, data = imap.fetch(latest_email_id, "(UID)")
    msg_uid = parse_uid(data[0])

    messages = int(messages[0])
    N = messages

    for i in range(messages, messages - N, -1):

        res, msg = imap.fetch(str(i), "(RFC822)")
        for response in msg:
            if isinstance(response, tuple):

                msg = email.message_from_bytes(response[1])

                if msg.is_multipart():

                    for part in msg.walk():
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            continue

                        try:
                            body = payload.decode('utf-8')
                            if is_it_junk(body):
                                move_mail(imap, msg_uid, dest)
                        except:
                            body = payload.decode('windows-1252')
                            if is_it_junk(body):
                                move_mail(imap, msg_uid, dest)

                        break
                else:

                    try:
                        body = msg.get_payload(decode=True).decode('utf-8')
                        if is_it_junk(body):
                            move_mail(imap, msg_uid, dest)
                    except:
                        body = msg.get_payload(decode=True).decode('windows-1252')
                        if is_it_junk(body):
                            move_mail(imap, msg_uid, dest)

    return 1


def check_incoming_mail(username, password, source, dest):
    try:

        imap = connect(username, password)
        check_past(imap, source, dest)
        buffer = None
        global stop_threads
        while not stop_threads:
            status, messages = imap.select(mailbox=source, readonly=False)
            resp, items = imap.search(None, 'All')
            email_ids = items[0].split()
            latest_email_id = email_ids[-1]

            resp, data = imap.fetch(latest_email_id, "(UID)")
            msg_uid = parse_uid(data[0])
            if buffer is None:
                buffer = msg_uid
            elif buffer == msg_uid:
                continue
            buffer = msg_uid
            N = 1

            messages = int(messages[0])
            body = None

            for i in range(messages, messages - N, -1):

                res, msg = imap.fetch(str(i), "(RFC822)")
                for response in msg:
                    if isinstance(response, tuple):

                        msg = email.message_from_bytes(response[1])

                        if msg.is_multipart():

                            for part in msg.walk():
                                payload = part.get_payload(decode=True)
                                if payload is None:
                                    continue

                                try:
                                    body = payload.decode('utf-8')
                                    if is_it_junk(body):
                                        move_mail(imap, msg_uid, dest)
                                except:
                                    body = payload.decode('windows-1252')
                                    if is_it_junk(body):
                                        move_mail(imap, msg_uid, dest)

                                break
                        else:

                            try:
                                body = msg.get_payload(decode=True).decode('utf-8')
                                if is_it_junk(body):
                                    move_mail(imap, msg_uid, dest)
                            except:
                                body = msg.get_payload(decode=True).decode('windows-1252')
                                if is_it_junk(body):
                                    move_mail(imap, msg_uid, dest)

    except KeyboardInterrupt:
        print('Program Exit Exception')
        disconnect(imap)
        return
    print('Scan stopped')
    disconnect(imap)


def check_input(url):
    np_arry = np.array([[(len(str(url))),
                         feature_extraction.hostname_len(url),
                         feature_extraction.path_len(url),
                         feature_extraction.fd_length(url),
                         feature_extraction.tld_length(url),
                         url.count('-'),
                         url.count('_'),
                         url.count('@'),
                         url.count('?'),
                         url.count('%'),
                         url.count('.'),
                         url.count('='),
                         url.count('http'),
                         url.count('https'),
                         url.count('www'),
                         feature_extraction.digit_count(url),
                         feature_extraction.letter_count(url),
                         feature_extraction.no_of_dir(url),
                         feature_extraction.having_ip_address(url),
                         feature_extraction.shortening_service(url),
                         feature_extraction.number_of_parameters(url),
                         feature_extraction.get_entropy(url),
                         feature_extraction.has_login_in_string(url),
                         feature_extraction.has_server_in_string(url),
                         feature_extraction.has_admin_in_string(url),
                         feature_extraction.has_client_in_string(url)]])

    df = pd.DataFrame(np_arry, columns=['url_length',
                                        'hostname_length',
                                        'path_length',
                                        'fd_length',
                                        'tld_length',
                                        'n-',
                                        'n_',
                                        'n@',
                                        'n?',
                                        'n%',
                                        'n.',
                                        'n=',
                                        'n-http',
                                        'n-https',
                                        'n-www',
                                        'n-digits',
                                        'n-letters',
                                        'n-dir',
                                        'use_of_ip',
                                        'short_url',
                                        'n_param',
                                        'entropy',
                                        'login',
                                        'server',
                                        'admin',
                                        'client',
                                        ])

    return df


def read_data(test_path):
    df_test = pd.read_csv(test_path)
    df_test = df_test.dropna()
    test_y = df_test['result']
    df_test = df_test.drop('url', axis=1)
    test_x = df_test.drop('result', axis=1)

    return test_x, test_y


def stop_scan():
    global scan_thread, strt_btn, stop_btn, stop_threads
    stop_threads = True
    stop_btn["state"] = "disabled"
    global scan_thread
    if scan_thread != None:
        scan_thread.join()
    strt_btn["state"] = "active"


def start_scan(email, password, source, dest):
    global scan_thread, strt_btn, stop_btn, stop_threads
    stop_threads = False
    strt_btn["state"] = "disabled"
    scan_thread = threading.Thread(target=check_incoming_mail, args=(email, password, source, dest))
    scan_thread.start()
    stop_btn["state"] = "active"
    print("Scan Start")


def print_statistics(train_x, test_y, log_model):
    coefs = pd.Series(index=train_x.columns, data=log_model.coef_[0])
    coefs = coefs.sort_values()

    plt.figure(figsize=(10, 6))
    plt.xticks(rotation=90)
    sns.barplot(x=coefs.index, y=coefs.values)
    plot_confusion_matrix(log_model, scaled_x_test, test_y)

    print(classification_report(test_y, y_pred))
    print(confusion_matrix(test_y, y_pred).ravel())
    plot_precision_recall_curve(log_model, scaled_x_test, test_y)
    plt.show()


is_there_fea = 0 # If you want to extract feature you should do this variable 1
source_data = "source_data/data_source.csv"
fea_data = "fea_data/data_feature.csv"

if not is_there_fea:
    my_features = feature_extraction.features(source_data, fea_data)
    my_features.extract_features()

start_time = time.time()

dtest_x, dtest_y = read_data(fea_data)

train_x, test_x, train_y, test_y = train_test_split(dtest_x, dtest_y, test_size=0.3, random_state=101)

scaler = StandardScaler()
scaled_x_train = scaler.fit_transform(train_x)
scaled_x_test = scaler.transform(test_x)

log_model = LogisticRegressionCV()
log_model.fit(scaled_x_train, train_y)
y_pred = log_model.predict(scaled_x_test)
print_statistics(train_x, test_y, log_model) # This function prints statistics

print("--- %s seconds ---" % (time.time() - start_time))

stop_threads = False
scan_thread = None
window = Tk()

lbl = Label(window, text="Ransomware Detector", fg='red', font=("Helvetica", 25))
lbl.place(x=70, y=50)
email_lbl = Label(window, text='Enter Gmail Account:', fg='blue')
email_lbl.place(x=30, y=150)
e_txtfld = Entry(window, bd=2)
e_txtfld.place(x=300, y=150)

pass_lbl = Label(window, text='Enter Password:', fg='blue')
pass_lbl.place(x=30, y=200)

p_txtfld = Entry(window, bd=2, show="*")
p_txtfld.place(x=300, y=200)

fol1_lbl = Label(window, text='Enter the name of the folder to search:', fg='blue')
fol1_lbl.place(x=30, y=250)

fol1_txtfld = Entry(window, bd=2)
fol1_txtfld.place(x=300, y=250)

fol2_lbl = Label(window, text='Enter the folder to which the mails will be sent:', fg='blue')
fol2_lbl.place(x=30, y=300)

fol2_txtfld = Entry(window, bd=2)
fol2_txtfld.place(x=300, y=300)
strt_btn = Button(window, text="Start Scanning", fg='green',
                  command=lambda: start_scan(e_txtfld.get(), p_txtfld.get(), fol1_txtfld.get(),
                                             fol2_txtfld.get()))
strt_btn.place(x=150, y=350)

stop_btn = Button(window, text="Stop Scanning", fg='red', state="disabled", command=lambda: stop_scan())
stop_btn.place(x=250, y=350)
window.title('Ransomware Detector')
window.geometry("500x400+10+10")
window.mainloop()
