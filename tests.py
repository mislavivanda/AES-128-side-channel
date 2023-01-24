import unittest
from hamming_weight import HW
from pearson import mean, pearsonCorrelationCoefficent
import aes


class TestSum(unittest.TestCase):

    def test_mean(self):
        self.assertEqual(mean([1, 2, 3, 4, 5]), 3, "Should be 3")

    def test_pearson(self):
        self.assertEqual(round(pearsonCorrelationCoefficent([1, 3, 2, 4, 7, 10, 6, 6, 8, 3], [
                         6, 8, 4, 7, 2, 1, 5, 9, 6, 5], 10), 4), -0.4346, "Should be -0.4346")

    def test_hamming_weight(self):
        self.assertEqual(HW(15), 4, "Should be 4")

    def test_aes_key_expansion_inverse(self):
        self.assertEqual(aes.aes128InverseKeyExpansion([0x89, 0xd8, 0xf2, 0x59, 0xd0, 0x92,
                                                        0x47, 0x0f, 0xe1, 0x56, 0x69, 0xfc, 0x83, 0x64, 0x05, 0x23]), '0x300x300x300x300x370x300x310x350x300x300x300x300x370x300x310x35', "Wrong inverse key expansion")


if __name__ == '__main__':
    unittest.main()
