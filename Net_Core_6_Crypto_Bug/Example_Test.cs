using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net_Core_6_Crypto_Bug.Code_Examples;

namespace Net_Core_6_Crypto_Bug
{
    [TestClass]
    public class Example_Test
    {
        [TestMethod]
        [DataRow("HelloWord", "123")]//Success
        [DataRow("{ \"text\" : \"Hello Wo?rd!\" }","123")]//Bug    
        public void Crypt_Then_Encrypt_Bug_Old(string data, string key)
        {           
            var crypted_data = Crypo_Old.Encrypt(data, key);
            var encrypted_data = Crypo_Old.Decrypt(crypted_data, key);

            Assert.IsTrue(data == encrypted_data, $"Expected: {data} Actual: {encrypted_data} ");
        }

        [TestMethod]
        [DataRow("HelloWord", "123")]//Success
        [DataRow("{ \"text\" : \"Hello Wo?rd!\" }", "123")]//Bug    
        public void Crypt_Then_Encrypt_Bug_New(string data, string key)
        {          
            var crypted_data = Crypo_New.Encrypt(data, key);
            var encrypted_data = Crypo_New.Decrypt(crypted_data, key);

            Assert.IsTrue(data == encrypted_data, $"Expected: {data} Actual: {encrypted_data} ");
        }
    }
}