package cz.vernjan.ctf.catch19;

import java.util.function.Consumer;

// https://www.geeksforgeeks.org/java-program-to-print-all-permutations-of-a-given-string/
public class Permutation {
//    public static void main(String[] args) {
//        String str = "ABCDEF";
//        int n = str.length();
//        Permutation permutation = new Permutation();
//        permutation.permute(str, 0, n - 1);
//    }

    /**
     * permutation function
     *
     * @param str string to calculate permutation for
     * @param l   starting index
     * @param r   end index
     */
    public static void permute(String str, int l, int r, Consumer<String> consumer) {
        if (l == r) {
            consumer.accept(str);
//            System.out.println(str);
        }
        else {
            for (int i = l; i <= r; i++) {
                str = swap(str, l, i);
                permute(str, l + 1, r, consumer);
                str = swap(str, l, i);
            }
        }
    }

    /**
     * Swap Characters at position
     *
     * @param a string value
     * @param i position 1
     * @param j position 2
     * @return swapped string
     */
    private static String swap(String a, int i, int j) {
        char temp;
        char[] charArray = a.toCharArray();
        temp = charArray[i];
        charArray[i] = charArray[j];
        charArray[j] = temp;
        return String.valueOf(charArray);
    }
}

// This code is contributed by Mihir Joshi