using AliaaCommon.Models;
using EasyMongoNet;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using TciDataLinks.Blazor.Shared.Models;

namespace TciDataLinks.Blazor.Server.Models
{
    [CollectionOptions(Name = nameof(AuthUser))]
    [CollectionSave(WriteLog = true)]
    [CollectionIndex(Fields: new string[] { nameof(Username) }, Unique = true)]
    [BsonIgnoreExtraElements]
    public class AuthUserX : ClientAuthUser
    {
        public string HashedPassword { get; set; }

        [BsonIgnore]
        public string Password
        {
            set
            {
                HashedPassword = AuthUserDBExtention.GetHash(value);
            }
        }
    }

    public static class AuthUserXDBExtention
    {
        public static AuthUserX CheckAuthentication(this IMongoCollection<AuthUserX> userCol, string username, string password, bool passwordIsHashed = false)
        {
            string hash;
            if (passwordIsHashed)
                hash = password;
            else
                hash = AuthUserDBExtention.GetHash(password);
            return userCol.FindFirst(u => u.Username == username && u.HashedPassword == hash && u.Disabled != true);
        }
    }
}
