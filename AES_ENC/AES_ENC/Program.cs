using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES_ENC
{
    public class Program
    {
        static void Main(string[] args)
        {
            string texto;
            Console.WriteLine("Ingresa Texto a Encriptar");
            texto = Console.ReadLine();
            string textoEncriptado = Cifrado(texto, "CIATEC.AC-F4DAltar", "hP*Dw%e45cpY@dt&");
            Console.WriteLine("Texto Cifrado: " + textoEncriptado);
            Console.ReadLine();

            Console.WriteLine("Descencriptar");
            

            string textodesencriptado = Descifrado(textoEncriptado, "CIATEC.AC-F4DAltar", "hP*Dw%e45cpY@dt&");
            Console.WriteLine("Texto Deifrado: " + textodesencriptado);

            Console.ReadLine();


        }
       static string Cifrado(string textoacifrar, string password, string clave)
        {
            AesManaged aes = null;
            MemoryStream streamenmemoria = null;
            CryptoStream streamcifrado = null;
            try
            {
                var rfc2898 = new Rfc2898DeriveBytes
                    (password, Encoding.UTF8.GetBytes(clave),10000);
                aes = new AesManaged();
                aes.Key = rfc2898.GetBytes(32);
                aes.IV = rfc2898.GetBytes(16);
                streamenmemoria = new MemoryStream();
                streamcifrado = new CryptoStream(streamenmemoria, aes.CreateEncryptor(),
                                                 CryptoStreamMode.Write);
                byte[] datos = Encoding.UTF8.GetBytes(textoacifrar);
                streamcifrado.Write(datos, 0, datos.Length);
                streamcifrado.FlushFinalBlock();
                return Convert.ToBase64String(streamenmemoria.ToArray());
            }
            catch (Exception ex)
            {
                //Toast.MakeText(this, ex.Message, ToastLength.Long).Show();
                return "error";
            }
            finally
            {
                if (streamcifrado != null)
                    streamcifrado.Close();

                if (streamenmemoria != null)
                    streamenmemoria.Close();

                if (aes != null)
                    aes.Clear();
            }
        }
        static string Descifrado(string textoadescifrar, string password, string clave)
        {
            AesManaged aes = null;
            MemoryStream streamenmemoria = null;
            try
            {
                Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(password,
                                                                    Encoding.UTF8.GetBytes(clave),
                                                                    10000);
                aes = new AesManaged();
                aes.Key = rfc2898.GetBytes(32);
                aes.IV = rfc2898.GetBytes(16);
                streamenmemoria = new MemoryStream();
                CryptoStream streamcifrado = new CryptoStream(streamenmemoria,
                                                             aes.CreateDecryptor(),
                                                             CryptoStreamMode.Write);
                byte[] datos = Convert.FromBase64String(textoadescifrar);
                streamcifrado.Write(datos, 0, datos.Length);
                streamcifrado.FlushFinalBlock();
                byte[] arreglodescifrado = streamenmemoria.ToArray();
                if (streamcifrado != null)
                    streamcifrado.Dispose();
                return Encoding.UTF8.GetString(arreglodescifrado, 0,
                                               arreglodescifrado.Length);
            }
            catch (Exception ex)
            {
                //Toast.MakeText(this, ex.Message, ToastLength.Long).Show();
                return "error";
            }
            finally
            {
                if (streamenmemoria != null)
                    streamenmemoria.Dispose();
                if (aes != null)
                    aes.Clear();
            }
        }
    }

}
