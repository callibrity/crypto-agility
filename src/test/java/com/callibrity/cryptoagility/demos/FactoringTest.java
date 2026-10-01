package com.callibrity.cryptoagility.demos;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class FactoringTest {

    @Nested
    class When_the_number_is_a_product_of_two_primes {

        @Test
        void finds_one_of_the_primes() {
            var rng = new Random(42);
            BigInteger p = BigInteger.probablePrime(24, rng);
            BigInteger q = BigInteger.probablePrime(24, rng);

            BigInteger factor = Factoring.findFactor(p.multiply(q));

            assertTrue(factor.equals(p) || factor.equals(q));
        }

        @Test
        void copes_with_very_small_numbers() {
            BigInteger factor = Factoring.findFactor(BigInteger.valueOf(15));

            assertTrue(factor.equals(BigInteger.valueOf(3)) || factor.equals(BigInteger.valueOf(5)));
        }
    }

    @Nested
    class When_the_number_is_even {

        @Test
        void returns_two() {
            assertEquals(BigInteger.TWO, Factoring.findFactor(BigInteger.valueOf(2 * 104729)));
        }
    }
}
