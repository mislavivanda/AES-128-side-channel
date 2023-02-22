import math


def pearsonCorrelationCoefficent(X, Y, N):
    X_mean = mean(X)
    Y_mean = mean(Y)
    numerator = 0
    denominator_X_part = 0
    denominator_Y_part = 0
    for i in range(N):
        numerator += (X[i] - X_mean) * (Y[i] - Y_mean)
        denominator_X_part += (X[i] - X_mean) ** 2
        denominator_Y_part += (Y[i] - Y_mean) ** 2
    denominator = math.sqrt(denominator_X_part * denominator_Y_part)
    if denominator == 0:  # ZA VELIKI BROJ UZORAKA JE MALA VJV DA SE DOGODI, SLUCAJ U KOJEM SU SVI CLANOVI ISTI PA ĆE I IZNOS ARITMETICKE SREDINE BITI ISTI KAO I SVI CLANOVI PA ĆE VRIJEDNOST BITI 0
        return 0
    else:
        return abs(numerator / denominator)


def mean(dataArray):
    sum = 0
    for i in range(len(dataArray)):
        sum += dataArray[i]
    return sum / len(dataArray)
