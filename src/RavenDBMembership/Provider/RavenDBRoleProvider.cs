namespace RavenDBMembership.Provider
{
    using Raven.Client;
    using Raven.Client.Embedded;
    using RavenDBMembership;
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Configuration;
    using System.Configuration.Provider;
    using System.Linq;
    using System.Web.Hosting;
    using System.Web.Security;

    public class RavenDBRoleProvider : RoleProvider
    {
        private static IDocumentStore _documentStore;
        private const string ProviderName = "RavenDBRole";

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            if((usernames.Length != 0) && (roleNames.Length != 0))
            {
                IDocumentSession session = DocumentStore.OpenSession();
                try
                {
                    IDocumentQuery<User> query = session.Advanced.LuceneQuery<User>().OpenSubclause();
                    foreach(string str in usernames)
                    {
                        query = query.WhereEquals("Username", str, true);
                    }
                    List<User> list = query.CloseSubclause().AndAlso().WhereEquals("ApplicationName", this.ApplicationName, true).ToList<User>();
                    IDocumentQuery<Role> query2 = session.Advanced.LuceneQuery<Role>().OpenSubclause();
                    foreach(string str2 in roleNames)
                    {
                        query2 = query2.WhereEquals("Name", str2, true);
                    }
                    foreach(string str3 in (from r in query2.CloseSubclause().AndAlso().WhereEquals("ApplicationName", this.ApplicationName) select r.Id).ToList<string>())
                    {
                        foreach(User user in list)
                        {
                            user.Roles.Add(str3);
                        }
                    }
                    session.SaveChanges();
                }
                catch(Exception exception)
                {
                    Console.WriteLine(exception.ToString());
                    throw;
                }
                finally
                {
                    if(session != null)
                    {
                        session.Dispose();
                    }
                }
            }
        }

        public static void AttachTo(IDocumentStore documentStore)
        {
            _documentStore = documentStore;
        }

        public override void CreateRole(string roleName)
        {
            IDocumentSession session = DocumentStore.OpenSession();
            try
            {
                Role entity = new Role(roleName, null)
                {
                    ApplicationName = this.ApplicationName
                };
                session.Store(entity);
                session.SaveChanges();
            }
            catch(Exception exception)
            {
                Console.WriteLine(exception.ToString());
                throw;
            }
            finally
            {
                if(session != null)
                {
                    session.Dispose();
                }
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            bool flag;
            IDocumentSession session = DocumentStore.OpenSession();
            try
            {
                Role role = (from r in session.Query<Role>()
                             where (r.Name == roleName) && (r.ApplicationName == this.ApplicationName)
                             select r).SingleOrDefault<Role>();
                if(role != null)
                {
                    List<User> source = (from u in session.Query<User>()
                                         where u.Roles.Any<string>(roleId => roleId == role.Id)
                                         select u).ToList<User>();
                    if(source.Any<User>() && throwOnPopulatedRole)
                    {
                        throw new Exception(string.Format("Role {0} contains members and cannot be deleted.", role.Name));
                    }
                    foreach(User user in source)
                    {
                        user.Roles.Remove(role.Id);
                    }
                    session.Delete<Role>(role);
                    session.SaveChanges();
                    return true;
                }
                flag = false;
            }
            catch(Exception exception)
            {
                Console.WriteLine(exception.ToString());
                throw;
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

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                Role role = (from r in session.Query<Role>()
                             where (r.Name == roleName) && (r.ApplicationName == this.ApplicationName)
                             select r).SingleOrDefault<Role>();
                if(role != null)
                {
                    return (from u in session.Query<User>()
                            where u.Roles.Contains(role.Id) && u.Username.Contains(usernameToMatch)
                            select u.Username).ToArray<string>();
                }
                return null;
            }
        }

        public override string[] GetAllRoles()
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                return (from r in (from r in session.Query<Role>()
                                   where r.ApplicationName == this.ApplicationName
                                   select r).ToList<Role>()
                        select r.Name).ToArray<string>();
            }
        }

        public override string[] GetRolesForUser(string username)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                Func<Role, bool> predicate = null;
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                if((user != null) && user.Roles.Any<string>())
                {
                    if(predicate == null)
                    {
                        predicate = r => user.Roles.Contains(r.Id);
                    }
                    return (from r in session.Query<Role>().ToList<Role>().Where<Role>(predicate) select r.Name).ToArray<string>();
                }
                return new string[0];
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                Role role = (from r in session.Query<Role>()
                             where (r.Name == roleName) && (r.ApplicationName == this.ApplicationName)
                             select r).SingleOrDefault<Role>();
                if(role != null)
                {
                    return (from u in session.Query<User>()
                            where u.Roles.Contains(role.Id)
                            select u.Username).ToArray<string>();
                }
                return null;
            }
        }

        private void InitConfigSettings(NameValueCollection config)
        {
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if(config == null)
            {
                throw new ArgumentNullException("There are not membership configuration settings.");
            }
            if(string.IsNullOrEmpty(name))
            {
                name = "RavenDBMembershipProvider";
            }
            if(string.IsNullOrEmpty(config["description"]))
            {
                config["description"] = "An Asp.Net membership provider for the RavenDB document database.";
            }
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
                    };
                    _documentStore = store;
                }
                else
                {
                    Raven.Client.Document.DocumentStore store2 = new Raven.Client.Document.DocumentStore
                    {
                        ConnectionStringName = config["connectionStringName"]
                    };
                    _documentStore = store2;
                }
                _documentStore.Initialize();
            }
            this.ApplicationName = string.IsNullOrEmpty(config["applicationName"]) ? HostingEnvironment.ApplicationVirtualPath : config["applicationName"];
            base.Initialize(name, config);
            this.InitConfigSettings(config);
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                User user = (from u in session.Query<User>()
                             where (u.Username == username) && (u.ApplicationName == this.ApplicationName)
                             select u).SingleOrDefault<User>();
                if(user != null)
                {
                    Role role = (from r in session.Query<Role>()
                                 where (r.Name == roleName) && (r.ApplicationName == this.ApplicationName)
                                 select r).SingleOrDefault<Role>();
                    if(role != null)
                    {
                        return user.Roles.Contains(role.Id);
                    }
                }
                return false;
            }
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            if((usernames.Length != 0) && (roleNames.Length != 0))
            {
                IDocumentSession session = DocumentStore.OpenSession();
                try
                {
                    IDocumentQuery<User> query = session.Advanced.LuceneQuery<User>().OpenSubclause();
                    foreach(string str in usernames)
                    {
                        query = query.WhereEquals("Username", str, true);
                    }
                    List<User> source = query.CloseSubclause().AndAlso().WhereEquals("ApplicationName", this.ApplicationName, true).ToList<User>();
                    IDocumentQuery<Role> query2 = session.Advanced.LuceneQuery<Role>().OpenSubclause();
                    foreach(string str2 in roleNames)
                    {
                        query2 = query2.WhereEquals("Name", str2, true);
                    }
                    using(List<string>.Enumerator enumerator = (from r in query2.CloseSubclause().AndAlso().WhereEquals("ApplicationName", this.ApplicationName) select r.Id).ToList<string>().GetEnumerator())
                    {
                        while(enumerator.MoveNext())
                        {
                            Func<User, bool> predicate = null;
                            string roleId = enumerator.Current;
                            if(predicate == null)
                            {
                                predicate = u => u.Roles.Contains(roleId);
                            }
                            foreach(User user in source.Where<User>(predicate))
                            {
                                user.Roles.Remove(roleId);
                            }
                        }
                    }
                    session.SaveChanges();
                }
                catch(Exception exception)
                {
                    Console.WriteLine(exception.ToString());
                    throw;
                }
                finally
                {
                    if(session != null)
                    {
                        session.Dispose();
                    }
                }
            }
        }

        public override bool RoleExists(string roleName)
        {
            using(IDocumentSession session = DocumentStore.OpenSession())
            {
                return session.Query<Role>().Any<Role>(r => (r.Name == roleName));
            }
        }

        public override string ApplicationName { get; set; }

        public static IDocumentStore DocumentStore
        {
            get
            {
                if(_documentStore == null)
                {
                    throw new NullReferenceException("The DocumentStore is not set. Please set the DocumentStore or make sure that the Common Service Locator can find the IDocumentStore and call Initialize on this provider.");
                }
                return _documentStore;
            }
            set
            {
                _documentStore = value;
            }
        }
    }
}
