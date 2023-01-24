import unittest
from hamming_weight import HW
from pearson import mean, pearsonCorrelationCoefficent


class TestSum(unittest.TestCase):

    def test_mean(self):
        self.assertEqual(mean([1, 2, 3, 4, 5]), 3, "Should be 3")

    def test_pearson(self):
        self.assertEqual(round(pearsonCorrelationCoefficent([1, 3, 2, 4, 7, 10, 6, 6, 8, 3], [
                         6, 8, 4, 7, 2, 1, 5, 9, 6, 5], 10), 4), -0.4346, "Should be -0.4346")

    def test_hamming_weight(self):
        self.assertEqual(HW(15), 4, "Should be 4")


if __name__ == '__main__':
    unittest.main()
