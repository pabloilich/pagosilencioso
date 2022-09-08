using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Specialized;

namespace secureacceptance
{
    public static class Security
    {
        private const String SECRET_KEY = "581bad639ed44af595740c7dc928a07d7396ae567094474d97d9fa9a1d8caec495d59beaafb84c1a9309e9fc0b511a5a3ac1bd80c1ce4b298603830f8ad9dde5fb9a97351d0d4864b8daf87be6f058cf54e2ce6ac9ea43f68537ae1d023a94b8fb943b4cab87465e8fce6ba09c73d340c34c69b9851c4c96b73a02de1fc14626";

        public static String sign(IDictionary<string, string> paramsArray)  {
            return sign(buildDataToSign(paramsArray), SECRET_KEY);
        }

        private static String sign(String data, String secretKey) {
            UTF8Encoding encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(secretKey);

            HMACSHA256 hmacsha256 = new HMACSHA256(keyByte);
            byte[] messageBytes = encoding.GetBytes(data);
            return Convert.ToBase64String(hmacsha256.ComputeHash(messageBytes));
        }

        private static String buildDataToSign(IDictionary<string,string> paramsArray) {
            String[] signedFieldNames = paramsArray["signed_field_names"].Split(',');
            IList<string> dataToSign = new List<string>();

	        foreach (String signedFieldName in signedFieldNames)
	        {
	             dataToSign.Add(signedFieldName + "=" + paramsArray[signedFieldName]);
	        }

            return commaSeparate(dataToSign);
        }

        private static String commaSeparate(IList<string> dataToSign) {
            return String.Join(",", dataToSign);                         
        }
    }
}
