using Raven.Abstractions;
using Raven.Database.Linq;
using System.Linq;
using System.Collections.Generic;
using System.Collections;
using System;
using Raven.Database.Linq.PrivateExtensions;
using Lucene.Net.Documents;
using System.Globalization;
using System.Text.RegularExpressions;
using Raven.Database.Indexing;

public class Index_Auto_Users_ByApplicationNameAndEmail : Raven.Database.Linq.AbstractViewGenerator
{
	public Index_Auto_Users_ByApplicationNameAndEmail()
	{
		this.ViewText = @"from doc in docs.Users
select new {
	ApplicationName = doc.ApplicationName,
	Email = doc.Email
}";
		this.ForEntityNames.Add("Users");
		this.AddMapDefinition(docs => 
			from doc in ((IEnumerable<dynamic>)docs)
			where string.Equals(doc["@metadata"]["Raven-Entity-Name"], "Users", System.StringComparison.InvariantCultureIgnoreCase)
			select new {
				ApplicationName = doc.ApplicationName,
				Email = doc.Email,
				__document_id = doc.__document_id
			});
		this.AddField("ApplicationName");
		this.AddField("Email");
		this.AddField("__document_id");
		this.AddQueryParameterForMap("ApplicationName");
		this.AddQueryParameterForMap("Email");
		this.AddQueryParameterForMap("__document_id");
		this.AddQueryParameterForReduce("ApplicationName");
		this.AddQueryParameterForReduce("Email");
		this.AddQueryParameterForReduce("__document_id");
	}
}
