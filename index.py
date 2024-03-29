import csv
import aes
from hamming_weight import HW
from pearson import pearsonCorrelationCoefficent
# Zbog jednostavnosti uzet uvijek isti plaintext
AES_key = [0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31,
           0x35, 0x30, 0x30, 0x30, 0x30, 0x37, 0x30, 0x31, 0x35]
payloadTexts = [
    [0xed, 0xc5, 0x51, 0x5e, 0x8c, 0x85, 0x85, 0x1e,
        0x92, 0x88, 0x9f, 0xea, 0x92, 0x17, 0x98, 0xe3],
    [0xd5, 0x83, 0x3c, 0x34, 0x87, 0x3c, 0x91, 0x32,
        0x71, 0x69, 0x82, 0x3f, 0x7c, 0x30, 0xd5, 0xc5],
    [0x11, 0xec, 0x48, 0x8f, 0x72, 0x2f, 0xb9, 0x5a,
        0xc1, 0xa9, 0x1c, 0x32, 0x91, 0x2e, 0xb0, 0xd4],
    [0xd, 0x9, 0xfe, 0x1a, 0x21, 0xdb, 0xf6, 0x64,
        0xb4, 0x5b, 0x2b, 0x6a, 0x94, 0x35, 0x5e, 0x8b],
    [0xbc, 0x25, 0x8e, 0x57, 0x77, 0x43, 0x26, 0x0,
        0xa4, 0xb5, 0xc, 0x5, 0x1a, 0x6d, 0xa6, 0xb1],
    [0x6c, 0x58, 0xb9, 0x32, 0x6a, 0x7f, 0x46, 0xb8,
        0xff, 0x9c, 0x8b, 0x16, 0x6b, 0x4a, 0x35, 0xd6],
    [0x24, 0xcb, 0x69, 0x33, 0xbc, 0x69, 0x25, 0xd0,
        0xe8, 0xf7, 0x44, 0x25, 0x82, 0x82, 0xcc, 0x24],
    [0xc7, 0x3f, 0x1f, 0xd1, 0x1e, 0x1b, 0xfc, 0x5a,
        0xc4, 0x86, 0x52, 0xb3, 0x1f, 0xc7, 0xa9, 0xf6],
    [0x24, 0x5c, 0xfa, 0x70, 0x66, 0xbf, 0x3f, 0xea,
        0xdb, 0x37, 0xb1, 0xa8, 0xe6, 0xc5, 0x5d, 0x16],
    [0xe5, 0xd0, 0x73, 0xdc, 0xbf, 0x5d, 0x5, 0x92,
        0xe1, 0x69, 0x37, 0xf8, 0x0, 0x4d, 0x71, 0x93],
    [0xb8, 0xea, 0x26, 0xaa, 0x3, 0x26, 0xd4, 0x50,
        0x2f, 0xfd, 0x9d, 0x52, 0xe6, 0xdb, 0xbc, 0x7],
    [0x2f, 0x5d, 0x37, 0xa6, 0x85, 0xc0, 0xab, 0xaa,
        0xea, 0x6d, 0x28, 0xa8, 0x89, 0x3a, 0x2d, 0xd4],
    [0x2, 0x15, 0x9b, 0xe9, 0x45, 0xb8, 0x31, 0x80,
        0xca, 0x2e, 0xe2, 0x20, 0x5c, 0xed, 0xb5, 0xa6],
    [0xac, 0x5d, 0xbb, 0x56, 0x42, 0x89, 0x92, 0x17,
        0x25, 0x86, 0x8d, 0xa6, 0xea, 0xdc, 0x4a, 0x69],
    [0xa6, 0xf2, 0x84, 0x6c, 0x85, 0xe1, 0x9b, 0x52,
        0x97, 0x7d, 0xd5, 0x28, 0x11, 0x4b, 0x4, 0x30],
    [0xc2, 0xb8, 0x72, 0x5b, 0x13, 0xb3, 0x19, 0x6b,
        0x14, 0x4, 0xe6, 0xdf, 0xd3, 0x44, 0xca, 0x10],
    [0xcd, 0x6e, 0x22, 0x21, 0x35, 0x8e, 0x5b, 0xf4,
        0xd0, 0x86, 0x48, 0xb9, 0x0, 0x5f, 0xf5, 0xa],
    [0x36, 0x6f, 0x3, 0x9c, 0x1d, 0x48, 0x9e, 0xb3,
        0x82, 0x57, 0x2d, 0xc8, 0xa, 0x8a, 0x20, 0xd9],
    [0x3, 0xe9, 0x46, 0xd7, 0x8d, 0xba, 0x1d, 0x6a,
        0x93, 0xc6, 0x10, 0xd2, 0x9b, 0x98, 0x1e, 0x7f],
    [0x71, 0x63, 0xb2, 0xd1, 0x81, 0xf1, 0xa5, 0x2d,
        0x38, 0x9f, 0x45, 0x21, 0x9b, 0xc1, 0x65, 0xd5],
    [0x5d, 0x12, 0xcd, 0xc5, 0x9d, 0x88, 0x5a, 0x50,
        0xde, 0x58, 0xa3, 0x66, 0x40, 0x3a, 0xc0, 0xc7],
    [0xa1, 0x7, 0x87, 0x31, 0xdc, 0xa7, 0x1c, 0xd1,
        0x89, 0xa0, 0x16, 0x7, 0x2b, 0x9, 0x4a, 0x8e],
    [0xa0, 0xb3, 0x91, 0xa8, 0x61, 0x4d, 0x80, 0xe5,
        0xce, 0x5a, 0x5c, 0x1f, 0xf9, 0xa6, 0x5c, 0xb8],
    [0xfd, 0x45, 0x86, 0xf4, 0x2c, 0x1e, 0xf8, 0xb,
        0xe0, 0xa0, 0x0, 0x3f, 0x78, 0xe2, 0x75, 0x12],
    [0x71, 0xcb, 0x1, 0x4f, 0x85, 0xb5, 0x37, 0x4e,
        0xdc, 0x5a, 0xce, 0xb, 0x1f, 0xac, 0x6, 0xf2],
    [0xfe, 0x1, 0x1e, 0x96, 0xcc, 0x8f, 0x7e, 0x8d,
        0xa3, 0x32, 0x28, 0xdc, 0xa4, 0x9e, 0xe1, 0x50],
    [0xe7, 0x28, 0x1, 0xf4, 0x3a, 0x57, 0x7f, 0x3c,
        0x2b, 0x1e, 0x54, 0xcb, 0xde, 0xbb, 0x77, 0x21],
    [0xf4, 0x24, 0xeb, 0x12, 0xee, 0xdb, 0x3f, 0x22,
        0x31, 0xa0, 0xe0, 0x36, 0x19, 0xc4, 0xf5, 0x32],
    [0xd4, 0x4b, 0x81, 0x2a, 0x2a, 0xf8, 0x64, 0x6c,
        0x8d, 0x95, 0xe1, 0x5e, 0x35, 0x4, 0x2c, 0x90],
    [0x6e, 0x8, 0x58, 0x6d, 0x4a, 0xa5, 0x2e, 0xdb,
        0xd, 0x85, 0x66, 0xbb, 0x44, 0x60, 0x1c, 0xfc],
]
# ZA SVAKI PLAIN CIPHER AKO JE LAST ROUND ODABRAN
cipherTexts = [
    [0xad, 0x53, 0x42, 0x14, 0xca, 0xac, 0xfe, 0xaf,
        0x8f, 0xc5, 0xba, 0x4c, 0xe8, 0x86, 0x39, 0xe5],
    [0xfd, 0x4a, 0xeb, 0x2, 0xa8, 0x12, 0xa4, 0x91,
        0x50, 0xb, 0xc7, 0x41, 0xad, 0xf0, 0x74, 0xf8],
    [0x68, 0x6c, 0x3, 0xc1, 0xad, 0x58, 0x8a, 0xfc,
        0x56, 0x94, 0xc4, 0x31, 0xda, 0xb1, 0x38, 0x67],
    [0x3d, 0xf6, 0xa9, 0x8c, 0x4a, 0x41, 0x8c, 0xfa,
        0xb4, 0xe5, 0x84, 0x5d, 0x59, 0x93, 0xe9, 0x77],
    [0x9e, 0x1, 0x61, 0xe7, 0x9b, 0xbf, 0xff, 0x13,
        0xab, 0x1e, 0x9b, 0xa6, 0x80, 0x4e, 0x97, 0xf9],
    [0xb4, 0x61, 0x2, 0xa4, 0x93, 0x45, 0x18, 0x4,
        0x8, 0xe0, 0xdd, 0x9a, 0x9d, 0x2b, 0xda, 0xe6],
    [0xbb, 0x5a, 0x25, 0x48, 0x78, 0xe6, 0xb3, 0xd0,
        0xd0, 0xfb, 0x6b, 0xfc, 0x62, 0x32, 0xf6, 0x61],
    [0x79, 0x6f, 0x6c, 0x53, 0xc2, 0xf2, 0x4b, 0x56,
        0xb1, 0xed, 0x49, 0xd0, 0x30, 0xe4, 0x59, 0x5c],
    [0xb7, 0xc7, 0xc9, 0x28, 0x75, 0x70, 0x4d, 0xaa,
        0xa5, 0xb2, 0xfd, 0xf5, 0x16, 0x60, 0x37, 0xf5],
    [0xfb, 0xb2, 0x8, 0xce, 0xbe, 0xfc, 0xdd, 0x5b,
        0xfa, 0x66, 0xa8, 0xc6, 0x36, 0x87, 0xc3, 0xd7],
    [0xc2, 0x8d, 0xd9, 0xad, 0x55, 0x16, 0xe, 0xec,
        0xc5, 0x7e, 0x3d, 0xbc, 0x81, 0x46, 0x48, 0x7c],
    [0x9d, 0x64, 0x72, 0xdb, 0x99, 0x32, 0xa3, 0x67,
        0x3d, 0x8d, 0x4e, 0x41, 0xf9, 0x10, 0xf1, 0xe7],
    [0xc5, 0x14, 0x0, 0x25, 0x6c, 0x44, 0xb4, 0x2d,
        0x49, 0x96, 0xa2, 0xf8, 0xf2, 0x6b, 0x5, 0xb5],
    [0x1b, 0x11, 0xa3, 0xc9, 0x17, 0xc5, 0xe7, 0x77,
        0xd6, 0x27, 0x4a, 0x29, 0xde, 0x9d, 0x25, 0x6d],
    [0x40, 0x18, 0x15, 0xbc, 0x45, 0x48, 0x6e, 0x24,
        0xc0, 0x75, 0xf1, 0xda, 0xd4, 0x86, 0x13, 0x34],
    [0x97, 0x5b, 0x62, 0xb7, 0xd2, 0x71, 0xe5, 0xa,
        0x4e, 0x9e, 0x42, 0xf7, 0xe7, 0x95, 0xac, 0x48],
    [0x7f, 0xba, 0xa1, 0x71, 0x9c, 0xf1, 0xdd, 0x2c,
        0x43, 0x65, 0x61, 0x23, 0x2, 0xaa, 0xa2, 0x3f],
    [0x2f, 0x3e, 0x9b, 0x49, 0x42, 0x62, 0xb2, 0xed,
        0x33, 0xcd, 0xc3, 0xbe, 0x48, 0xcc, 0x53, 0xa7],
    [0xb5, 0x86, 0x26, 0x61, 0xad, 0xad, 0xcc, 0xc5,
        0xaa, 0xf8, 0xe4, 0x6b, 0xc1, 0x82, 0xc3, 0x0],
    [0x58, 0x49, 0x27, 0x1d, 0x2a, 0xc1, 0xf1, 0xa8,
        0xdf, 0x74, 0xc8, 0xa3, 0x96, 0x38, 0x62, 0xa7],
    [0xa2, 0xbc, 0xd, 0x68, 0xcc, 0xdd, 0xd3, 0x72,
        0x37, 0x7d, 0xf8, 0x58, 0xab, 0x4, 0x9e, 0x11],
    [0xf, 0x54, 0x97, 0xd4, 0x44, 0x67, 0xa9, 0xfd,
        0xf2, 0x1, 0x96, 0xa0, 0x40, 0x17, 0x4c, 0xf0],
    [0x24, 0x9a, 0x14, 0xfe, 0x98, 0x61, 0xa7, 0x49,
        0x11, 0x6c, 0xb7, 0xa8, 0xa3, 0x9, 0x5, 0xe9],
    [0xff, 0x32, 0x7d, 0x76, 0x35, 0x79, 0x7a, 0xb2,
        0xfc, 0x59, 0xef, 0xfe, 0x40, 0xf8, 0xdb, 0x1b],
    [0xb8, 0x61, 0xfc, 0xde, 0x70, 0x32, 0x60, 0x2d,
        0xc2, 0x88, 0x30, 0x4, 0x44, 0xeb, 0x14, 0x19],
    [0x2e, 0xbb, 0x6c, 0xfe, 0x71, 0x34, 0x61, 0x9a,
        0x51, 0x2, 0xb3, 0x93, 0x40, 0xcc, 0xa, 0xfb],
    [0x33, 0x1e, 0x65, 0x79, 0xb3, 0xc1, 0x6c, 0x20,
        0xe6, 0xa9, 0x2, 0xaa, 0xba, 0x4d, 0x75, 0xf9],
    [0xf3, 0xf6, 0x71, 0x89, 0x24, 0x5c, 0xf1, 0xef,
        0xd9, 0x2b, 0xe, 0x31, 0x49, 0x69, 0x64, 0x4e],
    [0x71, 0xc8, 0xac, 0x5, 0xe5, 0x62, 0xc3, 0x71,
        0xec, 0x8a, 0x7d, 0xe0, 0x7, 0x5b, 0xe1, 0xa6],
    [0xc2, 0xe3, 0x35, 0x84, 0xaf, 0xda, 0xcb, 0x7b,
        0xc2, 0xd5, 0xe3, 0xca, 0xec, 0x2f, 0xc6, 0xa]
]
useFirstRoundLeakageModel = False


def firstRoundLeakageModel(plaintext, byteIndex, byteValue):
    return HW(aes.aesSubBytes(plaintext[byteIndex] ^ byteValue))


def lastRoundLeakageModel(cipher, byteIndex, byteValue):
    return HW(cipher[byteIndex] ^ byteValue)


leakageModel = firstRoundLeakageModel
if not useFirstRoundLeakageModel:
    leakageModel = lastRoundLeakageModel

sampleCount = 30  # broj snimanja
# broj uzoraka koji odgovaraju AES-u -> MORA BITI FIKSAN ODNOSNO ISTI ZA SVAKO SNIMANJE
EMLeakageCount = 2480
# Za svaki snimljeni trace pohrani sve snimljene uzorke koji predstavlja EM leakage
# U teoriji svaki snimljeni trace moze odgovarat razlicitom plaintextu
recordedTracesEMLeakages = [None] * sampleCount
for sampleIndex in range(sampleCount):
    with open('sample' + str(sampleIndex+1) + '.csv', newline='') as sampleCsvFile:
        fileContent = csv.reader(sampleCsvFile, delimiter=' ', quotechar='|')
        rowCounter = 0
        recordedTracesEMLeakages[sampleIndex] = []
        for row in fileContent:
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
for sampleIndex in range(sampleCount):
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
    targetText = payloadTexts[sampleIndex]
    if not useFirstRoundLeakageModel:
        targetText = cipherTexts[sampleIndex]
    for byteIndex in range(16):
        recordedTracesHWValues[sampleIndex].append([])
        for byteValue in range(256):
            recordedTracesHWValues[sampleIndex][byteIndex].append(
                leakageModel(targetText, byteIndex, byteValue))
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
targetRoundKey = [None] * 16
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
    targetRoundKey[i] = maximumValueByteValue
printInfoString = 'Guessed '
if useFirstRoundLeakageModel:
    printInfoString = 'FIRST'
else:
    printInfoString = 'LAST'
printInfoString += ' round key: '
targetRoundKeyString = ' '.join(str(e) for e in targetRoundKey)
print(printInfoString + targetRoundKeyString)
mainKey = ''
if useFirstRoundLeakageModel:
    mainKey = targetRoundKeyString
else:
    mainKey = aes.aes128InverseKeyExpansion(targetRoundKey)
print('Main key ' + mainKey)
