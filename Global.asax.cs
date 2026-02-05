using System.Web.Mvc;
using System.Web.Routing;

namespace MSEntraPOC
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }
    }
}
