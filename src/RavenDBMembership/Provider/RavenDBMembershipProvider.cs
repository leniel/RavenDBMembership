namespace RavenDBMembership.Provider
{
    using Raven.Client;
    using Raven.Client.Document;
    using Raven.Client.Embedded;
    using RavenDBMembership;
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Configuration;
    using System.Configuration.Provider;
    using System.Diagnostics;
    using System.Linq;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Web;
    using System.Web.Configuration;
    using System.Web.Hosting;
    using System.Web.Security;

    public class RavenDBMembershipProvider : MembershipProvider
    {
        private static IDocumentStore _documentStore;
        private bool _enablePasswordReset;
        private bool _enablePasswordRetrieval;
        private string _hashAlgorithm;
        private int _maxInvalidPasswordAttempts;
        private int _minRequiredNonAlphanumericCharacters;
        private int _minRequiredPasswordLength;
        private int _passwordAttemptWindow;
        private MembershipPasswordFormat _passwordFormat;
        private string _passwordStrengthRegularExpression;
        private bool _requiresQuestionAndAnswer;
        private bool _requiresUniqueEmail;
        private string _validationKey;
        private const string ProviderName = "RavenDBMembership";

        public static void AttachTo(IDocumentStore documentStore)
        {
            _documentStore = documentStore;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, newPassword, false);
            this.OnValidatingPassword(e);
            if(e.Cancel)
            {
                throw new MembershipPasswordException("The new password is not valid.");
            }
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                if(!this.ValidateUser(username, oldPassword))
                {
                    throw new MembershipPasswordException("Invalid username or old password. You must supply valid credentials to change your password.");
                }
                user.PasswordHash = this.EncodePassword(newPassword, user.PasswordSalt);
                session.SaveChanges();
            }
            return true;
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            if(!this.ValidateUser(username, password))
            {
                throw new MembershipPasswordException("You must supply valid credentials to change your question and answer.");
            }
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                user.PasswordQuestion = newPasswordQuestion;
                user.PasswordAnswer = this.EncodePassword(newPasswordAnswer, user.PasswordSalt);
                session.SaveChanges();
            }
            return true;
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            User user;
            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, password, true);
            this.OnValidatingPassword(e);
            if(e.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if((this._enablePasswordReset || this._enablePasswordRetrieval) && (this._requiresQuestionAndAnswer && string.IsNullOrEmpty(passwordAnswer)))
            {
                throw new ArgumentException("Requires question and answer is set to true and a question and answer were not provided.");
            }

            var salt = PasswordUtil.CreateRandomSalt();

            user = new User
            {
                Username = username,
                PasswordSalt = salt,
                PasswordHash = this.EncodePassword(password, salt),
                Email = email,
                ApplicationName = this.ApplicationName,
                DateCreated = DateTime.Now,
                PasswordQuestion = passwordQuestion,
                PasswordAnswer = string.IsNullOrEmpty(passwordAnswer) ? passwordAnswer : this.EncodePassword(passwordAnswer, salt),
                IsApproved = isApproved,
                IsLockedOut = false,
                IsOnline = false
            };

            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                if(this.RequiresUniqueEmail && ((from x in session.Query<User>()
                                                 where (x.Email == email) && (x.ApplicationName == this.ApplicationName)
                                                 select x).FirstOrDefault<User>() != null))
                {
                    status = MembershipCreateStatus.DuplicateEmail;
                    return null;
                }
                session.Store(user);
                session.SaveChanges();
                status = MembershipCreateStatus.Success;
                return new MembershipUser("RavenDBMembership", username, user.Id, email, passwordQuestion, user.Comment, isApproved, false, user.DateCreated, new DateTime(0x76c, 1, 1), new DateTime(0x76c, 1, 1), DateTime.Now, new DateTime(0x76c, 1, 1));
            }
        }

        public MembershipUser CreateUser(string username, string password, string email, string fullName, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            MembershipUser user = this.CreateUser(username, password, email, passwordQuestion, passwordAnswer, isApproved, providerUserKey, out status);
            if(user != null)
            {
                using(IDocumentSession session = _documentStore.OpenSession())
                {
                    session.Load<User>(user.ProviderUserKey.ToString()).FullName = fullName;
                    session.SaveChanges();
                }
            }
            return user;
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            bool flag;
            IDocumentSession session = DocumentStore.OpenSession();
            try
            {
                User entity = (from u in session.Query<User>()
                               where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                               select u).SingleOrDefault<User>();
                if(entity == null)
                {
                    throw new NullReferenceException("The user could not be deleted, they don't exist.");
                }
                session.Delete<User>(entity);
                session.SaveChanges();
                flag = true;
            }
            catch(Exception exception)
            {
                EventLog.WriteEntry(this.ApplicationName, exception.ToString());
                flag = false;
            }
            finally
            {
                if(session != null)
                {
                    session.Dispose();
                }
            }
            return flag;
        }

        private string EncodePassword(string password, string salt)
        {
            string str = password;
            switch(this._passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    return str;

                case MembershipPasswordFormat.Hashed:
                    if(string.IsNullOrEmpty(salt))
                    {
                        throw new ProviderException("A random salt is required with hashed passwords.");
                    }
                    return PasswordUtil.HashPassword(password, salt, this._hashAlgorithm, this._validationKey);

                case MembershipPasswordFormat.Encrypted:
                    return Convert.ToBase64String(this.EncryptPassword(Encoding.Unicode.GetBytes(password)));
            }
            throw new ProviderException("Unsupported password format.");
        }

        private MembershipUserCollection FindUsers(Func<User, bool> predicate, int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection users = new MembershipUserCollection();
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                IEnumerable<User> enumerable;
                IQueryable<User> source = from u in session.Query<User>()
                                          where u.ApplicationName == this.ApplicationName
                                          select u;
                if(predicate != null)
                {
                    enumerable = source.Where<User>(predicate);
                }
                else
                {
                    enumerable = source;
                }
                totalRecords = enumerable.Count<User>();
                foreach(User user in enumerable.Skip<User>((pageIndex * pageSize)).Take<User>(pageSize))
                {
                    users.Add(this.UserToMembershipUser(user));
                }
            }
            return users;
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return this.FindUsers(u => u.Email.Contains(emailToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return this.FindUsers(u => u.Username.Contains(usernameToMatch), pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            return this.FindUsers(null, pageIndex, pageSize, out totalRecords);
        }

        private string GetConfigValue(string value, string defaultValue)
        {
            if(string.IsNullOrEmpty(value))
            {
                return defaultValue;
            }
            return value;
        }

        public override int GetNumberOfUsersOnline()
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                return (from u in session.Query<User>()
                        where (u.ApplicationName == this.ApplicationName) && u.IsOnline
                        select u).Count<User>();
            }
        }

        public override string GetPassword(string username, string answer)
        {
            if(!this.EnablePasswordRetrieval)
            {
                throw new NotSupportedException("Password retrieval feature is not supported.");
            }
            if(this.PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                throw new NotSupportedException("Password retrieval is not supported with hashed passwords.");
            }
            User user = null;
            using(IDocumentSession session = _documentStore.OpenSession())
            {
                user = (from u in session.Query<User>()
                        where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                        select u).SingleOrDefault<User>();
                if(user == null)
                {
                    throw new NullReferenceException("The specified user does not exist.");
                }
                string str = this.EncodePassword(answer, user.PasswordSalt);
                if(this.RequiresQuestionAndAnswer && (user.PasswordAnswer != str))
                {
                    user.FailedPasswordAnswerAttempts++;
                    session.SaveChanges();
                    throw new MembershipPasswordException("The password question's answer is incorrect.");
                }
            }
            if(this.PasswordFormat == MembershipPasswordFormat.Clear)
            {
                return user.PasswordHash;
            }
            return this.UnEncodePassword(user.PasswordHash, user.PasswordSalt);
        }

        private User GetRavenDbUser(string username, bool userIsOnline)
        {
            using(IDocumentSession session = _documentStore.OpenSession())
            {
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                user.IsOnline = userIsOnline;
                session.SaveChanges();
                return user;
            }
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user = session.Load<User>(providerUserKey.ToString());
                if(user != null)
                {
                    return this.UserToMembershipUser(user);
                }
                return null;
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            User ravenDbUser = this.GetRavenDbUser(username, userIsOnline);
            if(ravenDbUser != null)
            {
                return this.UserToMembershipUser(ravenDbUser);
            }
            return null;
        }

        public override string GetUserNameByEmail(string email)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                return (from u in session.Query<User>()
                        where (u.Email == email) && (u.ApplicationName == this.ApplicationName)
                        select u.Username).SingleOrDefault<string>();
            }
        }

        private void InitConfigSettings(NameValueCollection config)
        {
            this.ApplicationName = this.GetConfigValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);
            this._maxInvalidPasswordAttempts = Convert.ToInt32(this.GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            this._passwordAttemptWindow = Convert.ToInt32(this.GetConfigValue(config["passwordAttemptWindow"], "10"));
            this._minRequiredNonAlphanumericCharacters = Convert.ToInt32(this.GetConfigValue(config["minRequiredAlphaNumericCharacters"], "1"));
            this._minRequiredPasswordLength = Convert.ToInt32(this.GetConfigValue(config["minRequiredPasswordLength"], "7"));
            this._passwordStrengthRegularExpression = Convert.ToString(this.GetConfigValue(config["passwordStrengthRegularExpression"], string.Empty));
            this._enablePasswordReset = Convert.ToBoolean(this.GetConfigValue(config["enablePasswordReset"], "true"));
            this._enablePasswordRetrieval = Convert.ToBoolean(this.GetConfigValue(config["enablePasswordRetrieval"], "true"));
            this._requiresQuestionAndAnswer = Convert.ToBoolean(this.GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            this._requiresUniqueEmail = Convert.ToBoolean(this.GetConfigValue(config["requiresUniqueEmail"], "true"));
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if(config == null)
            {
                throw new ArgumentNullException("There are no membership configuration settings.");
            }
            if(string.IsNullOrEmpty(name))
            {
                name = "RavenDBMembershipProvider";
            }
            if(string.IsNullOrEmpty(config["description"]))
            {
                config["description"] = "An Asp.Net membership provider for the RavenDB document database.";
            }
            base.Initialize(name, config);
            this.InitConfigSettings(config);
            this.InitPasswordEncryptionSettings(config);
            if(_documentStore == null)
            {
                if(string.IsNullOrEmpty(ConfigurationManager.ConnectionStrings[config["connectionStringName"]].ConnectionString))
                {
                    throw new ProviderException("The connection string name must be set.");
                }
                if(string.IsNullOrEmpty(config["enableEmbeddableDocumentStore"]))
                {
                    throw new ProviderException("RavenDB can run as a service or embedded mode, you must set enableEmbeddableDocumentStore in the web.config.");
                }
                if(Convert.ToBoolean(config["enableEmbeddableDocumentStore"]))
                {
                    EmbeddableDocumentStore store = new EmbeddableDocumentStore
                    {
                       ConnectionStringName = config["connectionStringName"]
                       //DataDirectory = "Data",
                       //RunInMemory = true
                    };

                    _documentStore = store;

                    RavenDBMembershipProvider.AttachTo(_documentStore);
                    RavenDBRoleProvider.AttachTo(_documentStore);
                }
                else
                {
                    DocumentStore store2 = new DocumentStore
                    {
                        ConnectionStringName = config["connectionStringName"]
                    };

                    _documentStore = store2;
                }

                _documentStore.Initialize();
            }
        }

        private void InitPasswordEncryptionSettings(NameValueCollection config)
        {
            MachineKeySection section = WebConfigurationManager.OpenWebConfiguration(HostingEnvironment.ApplicationVirtualPath).GetSection("system.web/machineKey") as MachineKeySection;
            this._hashAlgorithm = section.ValidationAlgorithm;
            this._validationKey = section.ValidationKey;
            if(section.ValidationKey.Contains("AutoGenerate") && (this.PasswordFormat != MembershipPasswordFormat.Clear))
            {
                throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
            }
            string str = config["passwordFormat"];
            if(str == null)
            {
                str = "Hashed";
            }
            switch(str)
            {
                case "Hashed":
                    this._passwordFormat = MembershipPasswordFormat.Hashed;
                    return;

                case "Encrypted":
                    this._passwordFormat = MembershipPasswordFormat.Encrypted;
                    return;

                case "Clear":
                    this._passwordFormat = MembershipPasswordFormat.Clear;
                    return;
            }
            throw new ProviderException("The password format from the custom provider is not supported.");
        }

        private bool IsLockedOutValidationHelper(User user)
        {
            long num = DateTime.Now.Ticks - user.LastFailedPasswordAttempt.Ticks;
            return ((user.FailedPasswordAttempts >= this.MaxInvalidPasswordAttempts) && (num < this.PasswordAttemptWindow));
        }

        public override string ResetPassword(string username, string answer)
        {
            string str2;
            if(!this.EnablePasswordReset)
            {
                throw new ProviderException("Password reset is not enabled.");
            }
            IDocumentSession session = DocumentStore.OpenSession();
            try
            {
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                if(user == null)
                {
                    throw new HttpException("The user to reset the password for could not be found.");
                }
                if(user.PasswordAnswer != this.EncodePassword(answer, user.PasswordSalt))
                {
                    user.FailedPasswordAttempts++;
                    session.SaveChanges();
                    throw new MembershipPasswordException("The password question's answer is incorrect.");
                }
                string password = Membership.GeneratePassword(8, 2);
                user.PasswordHash = this.EncodePassword(password, user.PasswordSalt);
                session.SaveChanges();
                str2 = password;
            }
            catch(Exception exception)
            {
                EventLog.WriteEntry(this.ApplicationName, exception.ToString());
                throw;
            }
            finally
            {
                if(session != null)
                {
                    session.Dispose();
                }
            }
            return str2;
        }

        private void SaveRavenUser(User user)
        {
            using(IDocumentSession session = _documentStore.OpenSession())
            {
                session.Store(user);
                session.SaveChanges();
            }
        }

        private string UnEncodePassword(string encodedPassword, string salt)
        {
            string s = encodedPassword;
            switch(this._passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    return s;

                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Hashed passwords do not require decoding, just compare hashes.");

                case MembershipPasswordFormat.Encrypted:
                    return Encoding.Unicode.GetString(this.DecryptPassword(Convert.FromBase64String(s)));
            }
            throw new ProviderException("Unsupported password format.");
        }

        public override bool UnlockUser(string userName)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user = (from x in session.Query<User>()
                             where (x.Username == userName) && (x.ApplicationName == this.ApplicationName)
                             select x).SingleOrDefault<User>();
                if(user == null)
                {
                    return false;
                }
                user.IsLockedOut = false;
                session.SaveChanges();
                return true;
            }
        }

        private User UpdatePasswordAttempts(User u, PasswordAttemptTypes attemptType, bool signedInOk)
        {
            long num = DateTime.Now.Ticks - u.LastFailedPasswordAttempt.Ticks;
            if(signedInOk || (num > this.PasswordAttemptWindow))
            {
                u.LastFailedPasswordAttempt = new DateTime(0x76c, 1, 1);
                u.FailedPasswordAttempts = 0;
                u.FailedPasswordAnswerAttempts = 0;
                this.SaveRavenUser(u);
                return u;
            }
            u.LastFailedPasswordAttempt = DateTime.Now;
            if(attemptType == PasswordAttemptTypes.PasswordAttempt)
            {
                u.FailedPasswordAttempts++;
            }
            else
            {
                u.FailedPasswordAnswerAttempts++;
            }
            if((u.FailedPasswordAttempts > this.MaxInvalidPasswordAttempts) || (u.FailedPasswordAnswerAttempts > this.MaxInvalidPasswordAttempts))
            {
                u.IsLockedOut = true;
            }
            this.SaveRavenUser(u);
            return u;
        }

        public override void UpdateUser(MembershipUser user)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user2 = (from u in session.Query<User>()
                              where (u.Username == user.UserName) && (u.ApplicationName == this.ApplicationName)
                              select u).SingleOrDefault<User>();
                if(user2 == null)
                {
                    throw new HttpException("The user to update could not be found.");
                }
                user2.Username = user.UserName;
                user2.Email = user.Email;
                user2.DateCreated = user.CreationDate;
                user2.DateLastLogin = new DateTime?(user.LastLoginDate);
                user2.IsOnline = user.IsOnline;
                user2.IsApproved = user.IsApproved;
                user2.IsLockedOut = user.IsLockedOut;
                session.SaveChanges();
            }
        }

        private MembershipUser UserToMembershipUser(User user)
        {
            return new MembershipUser("RavenDBMembership", user.Username, user.Id, user.Email, user.PasswordQuestion, user.Comment, user.IsApproved, user.IsLockedOut, user.DateCreated, user.DateLastLogin.HasValue ? user.DateLastLogin.Value : new DateTime(0x76c, 1, 1), new DateTime(0x76c, 1, 1), new DateTime(0x76c, 1, 1), new DateTime(0x76c, 1, 1));
        }

        public override bool ValidateUser(string username, string password)
        {
            if(!string.IsNullOrEmpty(username))
            {
                using(IDocumentSession session = DocumentStore.OpenSession())
                {
                    User user = (from u in session.Query<User>()
                                 where u.Username == username
                                 select u).SingleOrDefault<User>();
                    if(user == null)
                    {
                        return false;
                    }
                    if(user.PasswordHash == this.EncodePassword(password, user.PasswordSalt))
                    {
                        user.DateLastLogin = new DateTime?(DateTime.Now);
                        user.IsOnline = true;
                        user.FailedPasswordAttempts = 0;
                        user.FailedPasswordAnswerAttempts = 0;
                        session.SaveChanges();
                        return true;
                    }
                    user.LastFailedPasswordAttempt = DateTime.Now;
                    user.FailedPasswordAttempts++;
                    user.IsLockedOut = this.IsLockedOutValidationHelper(user);
                    session.SaveChanges();
                }
            }
            return false;
        }

        public override string ApplicationName { get; set; }

        public static IDocumentStore DocumentStore
        {
            get
            {
                return _documentStore;
            }
            set
            {
                _documentStore = value;
            }
        }

        public override bool EnablePasswordReset
        {
            get
            {
                return this._enablePasswordReset;
            }
        }

        public override bool EnablePasswordRetrieval
        {
            get
            {
                return this._enablePasswordRetrieval;
            }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get
            {
                return this._maxInvalidPasswordAttempts;
            }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get
            {
                return this._minRequiredNonAlphanumericCharacters;
            }
        }

        public override int MinRequiredPasswordLength
        {
            get
            {
                return this._minRequiredPasswordLength;
            }
        }

        public override int PasswordAttemptWindow
        {
            get
            {
                return this._passwordAttemptWindow;
            }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get
            {
                return this._passwordFormat;
            }
        }

        public override string PasswordStrengthRegularExpression
        {
            get
            {
                return this._passwordStrengthRegularExpression;
            }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get
            {
                return this._requiresQuestionAndAnswer;
            }
        }

        public override bool RequiresUniqueEmail
        {
            get
            {
                return this._requiresUniqueEmail;
            }
        }
    }
}
