import csv
import aes
from hamming_weight import HW
from pearson import pearsonCorrelationCoefficent
# Zbog jednostavnosti uzet uvijek isti plaintext
payloadTexts = [
    [0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31, 0x35,
        0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31, 0x35],
    [0x37, 0x31, 0x37, 0x30, 0x37, 0x30, 0x31, 0x35,
        0x30, 0x31, 0x31, 0x35, 0x37, 0x35, 0x31, 0x35]
]
dataRowStartIndex = 17
sampleCount = 2  # broj snimanja
# broj uzoraka koji odgovaraju AES-u -> MORA BITI FIKSAN ODNOSNO ISTI ZA SVAKO SNIMANJE
EMLeakageCount = 4000
# Za svaki snimljeni trace pohrani sve snimljene uzorke koji predstavlja EM leakage
# U teoriji svaki snimljeni trace moze odgovarat razlicitom plaintextu
recordedTracesEMLeakages = [None] * sampleCount
for sampleIndex in range(sampleCount):
    with open('sample' + str(sampleIndex+1) + '.csv', newline='') as sampleCsvFile:
        fileContent = csv.reader(sampleCsvFile, delimiter=' ', quotechar='|')
        rowCounter = 0
        recordedTracesEMLeakages[sampleIndex] = []
        for row in fileContent:
            if rowCounter >= dataRowStartIndex:
                time = row[0].split(',')[0]
                value = float(row[0].split(',')[1])
                recordedTracesEMLeakages[sampleIndex].append(value)
            rowCounter += 1
# print(recordedTracesEMLeakages[sampleIndex])
# Za svaki trace izracunaj HW vrijednosti
# HW sluzi kao model koji korelira EM zracenje i AES operacije
# Grupiramo po bajtovima plaintexta jer se AES operacije u rundi izvrsavaju na razini bajtova odnosno za svaki bajt posebno
# Dakle za svaki bajt će se odradit supstitucija i XOR sa odgovarajućim bajtom od ključa runde
# Na ovaj način ćemo otkrivat svaki bajt od ključa runde posebno a oni ce svi zajedno cinit cijeli ključ runde
# Buduci da mi ne znamo kljuc pa tako ni njegove bajtove racunamo HW za svaku mogucnost(BRUTEFORCE) -> buduci da se radi o bajtu to je [0-255]
recordedTracesHWValues = [None] * sampleCount
AES_key = [0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31,
           0x35, 0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31, 0x35]
plaintext = [0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31,
             0x35, 0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31, 0x35]
cypher = aes.enc(AES_key, plaintext)
aes.aes128InverseKeyExpansion([0x89, 0xd8, 0xf2, 0x59, 0xd0, 0x92,
                              0x47, 0x0f, 0xe1, 0x56, 0x69, 0xfc, 0x83, 0x64, 0x05, 0x23])
print(cypher)
""" for sampleIndex in range(sampleCount):
    recordedTracesHWValues[sampleIndex] = []
    # NAPADAMO ZADNJU OPERACIJU U ZADNJOJ RUNDI AES-A JE XORANJE BAJTOVA SA LAST ROUND KEY
    # IZLAZ TOGA JE ZAPRAVO KRAJNJI REZULTAT AES-A ODNOSNO CIPHERTEXT
    # MI TREBAMO DOBIT VRIJEDNOSTI BAJTOVA KOJE SE XOR-aju SA LAST ROUND KEY
    # TO DOBIJEMO SAMO TAKO DA XORAMO NAZAD SA KEY BAJTOM
    # PRISTUP SE MOZE TEMELJIT NA TOME DA ZNAMO CIPHERTEXT(SNIFFAMO PROMET PA GA ZNAMO) I ZNAMO PLAINTEXT(NEN UZNO DA MI SALJEMO NEGO NPR SENZOR ZA TEMEPRATURU ZNAMO KOLIKA JE TEMEPRATURA)
    # KAKO ZNAMO PAROVE PLAINTEXT I CIPHERTEXT ONDA MOZEMO RECOVERAT ISTO KLJUC TAGO DA TARGETAMO ZADNJU OPERACIJU U ZADNJOJ RUNDI
    # PROBAJ TO AKO NE USPIJE SIDE CHANNELO SA PRVOM RUNDOM
    # ONDA NAM JE POTREBAN KEY EXPANSION ALGORITAM ZA DOBIT PRAVE KLJUCEVE
    # ZASAD TARGETAT PRVU RUNDU IAKO NEMA DOVOLJNO ENTROPIJE U PLAINTEXTU, MINJA SE SAMO FRAME COUNT
    for byteIndex in range(16):
        recordedTracesHWValues[sampleIndex].append([])
        for byteValue in range(256):
            recordedTracesHWValues[sampleIndex][byteIndex].append(
                HW(aes.aesSubBytes(payloadTexts[sampleIndex][byteIndex] ^ byteValue)))
# Izracunaj perasonove koeficijente korelacije izmedu snimljenih EM signala i izracunatih HW vrijednosti ZA SVAKI SNIMLJENI EM UZORAK
# Koeficijente racunamo za svaki EM uzorak i grupiramo po BAJTU
# Za svaki bajt imat ćemo EMLeakageCount(jer racunamo za svaki EM leakage korelaciju sa HW kandidatom) Pearson koeficijenata
# ZA SVAKI EM LEAKAGE RACUNAMO PERASON KOEFICIJENTE ZA SVAKU MOGUCNOST BAJTA KLJUCA
# DRUGIM RIJECIMA ZA SVAKI EM LEAKAGE RACUNAMO VJV DA ON PREDSTAVLJA OPERACIJU SubBytes(Plaintext[B] XOR KANDIDATZABAJT)
pearsonCorrelationCoefficientValues = [None] * 16
for i in range(16):
    pearsonCorrelationCoefficientValues[i] = []
    for j in range(EMLeakageCount):
        pearsonCorrelationCoefficientValues[i].append([])
        for k in range(EMLeakageCount):
            pearsonCorrelationCoefficientValues[i][j] = []
# print(pearsonCorrelationCoefficientValues[0])
pearsonX = [None] * sampleCount  # snimljeni EM uzorci
pearsonY = [None] * sampleCount  # izracunati HW
for i in range(EMLeakageCount):
    for byteIndex in range(16):
        # pohrana pearson koeficijenta za svaku mogucnost bajt vrijednosti
        # pearsonCorrelationCoefficientValues = [None] * 256
        for byteValue in range(256):
            # racunaj Pearsona iz snimljenih sampleNumbers vrijednosti od EM tracea i sampleNumbers izracunatih HW vrijednosti
            # napuni pearsonX i perasonY nizove
            for j in range(sampleCount):
                pearsonX[j] = recordedTracesEMLeakages[j][i]
                pearsonY[j] = recordedTracesHWValues[j][byteIndex][byteValue]
            pearsonCorrelationCoefficientValues[byteIndex][i].append(pearsonCorrelationCoefficent(
                pearsonX, pearsonY, sampleCount))
# Pronadi max Pearson koeficijent korelacije za svaki BAJT
# ZA SVAKI UZORAK IMAMO IZRACUNAT Pearson KOEFICIJENT ZA SVAKU MOGUCU VRIJEDNOST byteValue OD 0-255
# PRVO ZA SVAKI EM UZORAK PRONADI MAX PERASON OD TIH 256 VRIJEDNOSTI(ZAPAMTI ZA KOJU VRIJEDNOST)
# NAKON TOGA ODREDI MAX VRIJEDNOST IZMEDU SVIH UZORAKA
# ONAJ byteValue ZA KOJEG SMO DOBILI MAX JE NAS PRETPOSTAVLJENI B-ti BAJT KLJUCA RUNDE -> TAJ EM UZORAK PREDSTAVLJA SUBBYTES() OPERACIJU S PRAVOM VRIJEDNOSTI KLJUCA
# TO ZAPRAVO ODGOVARA PRETRAZIVANJU MATRICE EMLeakageCount * 256
maximumValueByteValue = None
maximumValue = None
firstRoundKey = ''
for i in range(16):
    # Postavi max na prvi clan
    maximumValue = pearsonCorrelationCoefficientValues[i][0][0]
    maximumValueByteValue = 0
    for j in range(EMLeakageCount):
        for k in range(256):
            if pearsonCorrelationCoefficientValues[i][j][k] > maximumValue:
                maximumValue = pearsonCorrelationCoefficientValues[i][j][k]
                maximumValueByteValue = k
    print("Byte " + str(i+1) + ':' + str(maximumValueByteValue))
    print('Pearson value: ' + str(maximumValue))
    firstRoundKey += hex(maximumValueByteValue)
print('Guessed first round key: ' + firstRoundKey) """
