using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net_Core_6_Crypto_Bug.Code_Examples;
using System.Threading.Tasks;

namespace Net_Core_6_Crypto_Bug
{
    [TestClass]
    public class Example_Test
    {
    

        [TestMethod]
        [DataRow("HelloWord", "123")]//Success
        [DataRow("{ \"text\" : \"Hello Wo?rd!\" }", "123")]//Bug    
        public async Task Crypt_Then_Encrypt_Bug_NewAsync(string data, string key)
        {          
            var crypted_data =  await Crypo_New.Encrypt(data, key);
            var encrypted_data = await Crypo_New.Decrypt(crypted_data, key);

            Assert.IsTrue(data == encrypted_data, $"Expected: {data} Actual: {encrypted_data} ");
        }
    }
}