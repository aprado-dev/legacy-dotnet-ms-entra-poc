using System.Web.Mvc;

namespace MSEntraPOC.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = "Bem-vindo ao POC MS Entra!";
            return View();
        }
    }
}
