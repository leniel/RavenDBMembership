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

public class Index_Auto_Users_ByApplicationName : Raven.Database.Linq.AbstractViewGenerator
{
	public Index_Auto_Users_ByApplicationName()
	{
		this.ViewText = @"from doc in docs.Users
select new {
	ApplicationName = doc.ApplicationName
}";
		this.ForEntityNames.Add("Users");
		this.AddMapDefinition(docs => 
			from doc in ((IEnumerable<dynamic>)docs)
			where string.Equals(doc["@metadata"]["Raven-Entity-Name"], "Users", System.StringComparison.InvariantCultureIgnoreCase)
			select new {
				ApplicationName = doc.ApplicationName,
				__document_id = doc.__document_id
			});
		this.AddField("ApplicationName");
		this.AddField("__document_id");
		this.AddQueryParameterForMap("ApplicationName");
		this.AddQueryParameterForMap("__document_id");
		this.AddQueryParameterForReduce("ApplicationName");
		this.AddQueryParameterForReduce("__document_id");
	}
}
