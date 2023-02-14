#!/usr/bin/env python3

import unittest
import random
import string
from app.GhidraGolf import GhidraRunner, GGStruct


class TestSubmissions(unittest.TestCase):
    """Testing submission objects."""

    def setUp(self):
        """setup object for testing submissions."""
        self.gr = GhidraRunner(None, None, None, None, None)
        self.fname = list(string.ascii_letters)
        random.shuffle(self.fname)

    def test_data_sanitization_emptyobject(self):
        """Assess empty object is false."""
        GSTestObj = None
        res = self.gr.data_sanitization(GSTestObj)
        self.assertTrue(res)

    def test_data_sanitization_challengeid(self):
        """Assess challenge id is within hard coded range."""
        GSTestObj = GGStruct()
        GSTestObj.challenge_id = random.randint(200, 2000)
        res = self.gr.data_sanitization(GSTestObj)
        self.assertTrue(res)

        GSTestObj.challenge_id = random.randint(1, 100)
        GSTestObj.filename = "test.java"
        res = self.gr.data_sanitization(GSTestObj)
        self.assertFalse(res)

    def test_data_sanitization_challengename(self):
        """Assess challenge name is not invalid input."""
        GSTestObj = GGStruct()
        GSTestObj.challenge_id = random.randint(1, 100)

        # safe name
        GSTestObj.filename = "".join(self.fname[0:10]) + ".java"
        res = self.gr.data_sanitization(GSTestObj)
        self.assertFalse(res)

        upperBound = random.randint(0, len(string.punctuation))
        GSTestObj.filename = string.punctuation[0:upperBound] + ".java"
        res = self.gr.data_sanitization(GSTestObj)
        self.assertTrue(res)


if __name__ == '__main__':
    unittest.main()
