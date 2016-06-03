namespace RavenDBMembership
{
    using System;
    using System.Collections.Generic;

    public class User
    {
        public User()
        {
            this.Roles = new List<string>();
            this.Id = "authorization/users/";
        }

        public string ApplicationName { get; set; }

        public string Comment { get; set; }

        public DateTime DateCreated { get; set; }

        public DateTime? DateLastLogin { get; set; }

        public string Email { get; set; }

        public int FailedPasswordAnswerAttempts { get; set; }

        public int FailedPasswordAttempts { get; set; }

        public string FullName { get; set; }

        public string Id { get; set; }

        public bool IsApproved { get; set; }

        public bool IsLockedOut { get; set; }

        public bool IsOnline { get; set; }

        public DateTime LastFailedPasswordAttempt { get; set; }

        public string PasswordAnswer { get; set; }

        public string PasswordHash { get; set; }

        public string PasswordQuestion { get; set; }

        public string PasswordSalt { get; set; }

        public IList<string> Roles { get; set; }

        public string Username { get; set; }
    }
}
