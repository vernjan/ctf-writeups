using System;
using System.Security.Cryptography;
using System.Text;

namespace BadMorals
{
	// Token: 0x02000002 RID: 2
	public class Program
	{
		// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
		public static void Main(string[] args)
		{
			try
			{
				Console.Write("Your first input: ");
				char[] array = Console.ReadLine().ToCharArray();
				string text = "";
				for (int i = 0; i < array.Length; i++)
				{
					if (i % 2 == 0 && i + 2 <= array.Length)
					{
						text += array[i + 1].ToString();
					}
				}
				string str;
				if (text == "BumBumWithTheTumTum")
				{
					str = string.Concat(new object[]
					{
						"SFYyMH",
						array[17].ToString(),
						"yMz",
						array[8].GetHashCode() % 10,
						"zcnMzXzN",
						array[3].ToString(),
						"ZzF",
						array[9].ToString(),
						"MzNyM",
						array[13].ToString(),
						"5n",
						array[14].ToString(),
						"2"
					});
				}
				else
				{
					if (text == "")
					{
						Console.WriteLine("Your input is not allowed to result in an empty string");
						return;
					}
					str = text;
				}
				Console.Write("Your second input: ");
				char[] array2 = Console.ReadLine().ToCharArray();
				text = "";
				Array.Reverse(array2);
				for (int j = 0; j < array2.Length; j++)
				{
					text += array2[j].ToString();
				}
				string s;
				if (text == "BackAndForth")
				{
					s = string.Concat(new string[]
					{
						"Q1RGX3",
						array2[11].ToString(),
						"sNH",
						array2[8].ToString(),
						"xbm",
						array2[5].ToString(),
						"f"
					});
				}
				else
				{
					if (text == "")
					{
						Console.WriteLine("Your input is not allowed to result in an empty string");
						return;
					}
					s = text;
				}
				Console.Write("Your third input: ");
				char[] array3 = Console.ReadLine().ToCharArray();
				text = "";
				byte b = 42;
				for (int k = 0; k < array3.Length; k++)
				{
					char c = array3[k] ^ (char)b;
					b = (byte)((int)b + k - 4);
					text += c.ToString();
				}
				string str2;
				if (text == "DinosAreLit")
				{
					str2 = string.Concat(new string[]
					{
						"00ZD",
						array3[3].ToString(),
						"f",
						array3[2].ToString(),
						"zRzeX0="
					});
				}
				else
				{
					if (text == "")
					{
						Console.WriteLine("Your input is not allowed to result in an empty string");
						return;
					}
					str2 = text;
				}
				byte[] array4 = Convert.FromBase64String(str + str2);
				byte[] array5 = Convert.FromBase64String(s);
				byte[] array6 = new byte[array4.Length];
				for (int l = 0; l < array4.Length; l++)
				{
					array6[l] = (array4[l] ^ array5[l % array5.Length]);
				}
				byte[] array7 = SHA1.Create().ComputeHash(array6);
				byte[] array8 = new byte[]
				{
					107,
					64,
					119,
					202,
					154,
					218,
					200,
					113,
					63,
					1,
					66,
					148,
					207,
					23,
					254,
					198,
					197,
					79,
					21,
					10
				};
				for (int m = 0; m < array7.Length; m++)
				{
					if (array7[m] != array8[m])
					{
						Console.WriteLine("Your inputs do not result in the flag.");
						return;
					}
				}
				string @string = Encoding.ASCII.GetString(array4);
				if (@string.StartsWith("HV20{"))
				{
					Console.WriteLine("Congratulations! You're now worthy to claim your flag: {0}", @string);
				}
			}
			catch
			{
				Console.WriteLine("Please try again.");
			}
			finally
			{
				Console.WriteLine("Press enter to exit.");
				Console.ReadLine();
			}
		}
	}
}
