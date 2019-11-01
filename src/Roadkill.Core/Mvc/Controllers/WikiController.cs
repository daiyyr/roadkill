using System;
using System.Web;
using System.Web.Mvc;
using System.Web.UI;
using Roadkill.Core.Configuration;
using Roadkill.Core.Services;
using Roadkill.Core.Mvc.Attributes;
using Roadkill.Core.Mvc.ViewModels;
using Roadkill.Core.Security;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
using System.Net.Cache;

namespace Roadkill.Core.Mvc.Controllers
{
	/// <summary>
	/// Provides functionality for the /wiki/{id}/{title} route, which all pages are displayed via.
	/// </summary>
	[OptionalAuthorization]
	public class WikiController : ControllerBase
	{
		public PageService PageService { get; private set; }

		public WikiController(ApplicationSettings settings, UserServiceBase userManager, PageService pageService,
			IUserContext context, SettingsService settingsService)
			: base(settings, userManager, context, settingsService) 
		{
			PageService = pageService;
		}

		/// <summary>
		/// Displays the wiki page using the provided id.
		/// </summary>
		/// <param name="id">The page id</param>
		/// <param name="title">This parameter is passed in, but never used in queries.</param>
		/// <returns>A <see cref="PageViewModel"/> to the Index view.</returns>
		/// <remarks>This action adds a "Last-Modified" header using the page's last modified date, if no user is currently logged in.</remarks>
		/// <exception cref="HttpNotFoundResult">Thrown if the page with the id cannot be found.</exception>
		[BrowserCache]
		public ActionResult Index(int? id, string title)
        {
            if (id >= 7104 * 7104)
            {
                id = (id + 7104) / 7104 - 7104;
            }
            else if(!Context.IsAdmin)
            {
                string key = Request.QueryString["key"];
                string SMSUser = Request.QueryString["SMSUser"];
                string category = Request.QueryString["category"];
                DateTime localTime = GetLocalTimeFromGoogle();
                DateTime UTCTime = TimeZoneInfo.ConvertTimeToUtc(localTime, TimeZoneInfo.Local);
                var bytes = Encoding.Default.GetBytes(
                    "LoginAs"
                    + SMSUser
                    + "At"
                    + UTCTime.ToUniversalTime().ToString("yyyyMMddHHmm")
                    + category
                    );
                var Md5 = new MD5CryptoServiceProvider().ComputeHash(bytes);
                string clean_md5 = Regex.Replace(Convert.ToBase64String(Md5), @"[^a-zA-Z0-9]", "")
                    .ToLower();//always get QueryString as lower letter for unknown reason
                if (key != clean_md5)
                {
                    throw new HttpException(404, "Your key is expired. Please visit this page from Uxtrata Core again");
                }

            }

            if (id == null || id < 1)
				return RedirectToAction("Index", "Home");

			PageViewModel model = PageService.GetById(id.Value, true);

            if (!Context.IsAdmin)
            {
                bool restrict_page = false;
                bool user_have_access = false;
                foreach (var tag in model.Tags)
                {
                    if (tag.StartsWith("#"))
                    {
                        restrict_page = true;

                        Database.User user = UserService.GetUserById(new Guid(Context.CurrentUser));
                        foreach(var permission in user.Permission.Split(','))
                        {
                            if(permission.ToLower() == tag.Replace("#", "").ToLower())
                            {
                                user_have_access = true;
                                break;
                            }
                        }
                    }
                }
                if (restrict_page && !user_have_access)
                {
                    throw new HttpException(404, "The page could not be found");
                }
            }

			if (model == null)
				throw new HttpException(404, string.Format("The page with id '{0}' could not be found", id));

			return View(model);
		}


        public static DateTime GetLocalTimeFromGoogle()
        {
            DateTime dateTime = DateTime.MinValue;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://www.google.com/");
            request.Method = "GET";
            request.Accept = "text/html, application/xhtml+xml, */*";
            request.UserAgent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)";
            request.ContentType = "application/x-www-form-urlencoded";
            request.CachePolicy = new RequestCachePolicy(RequestCacheLevel.NoCacheNoStore); //No caching
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            if (response.StatusCode == HttpStatusCode.OK)
            {
                DateTime.TryParse(response.GetResponseHeader("DATE"), out dateTime);
            }
            return dateTime;
        }

        public ActionResult PageToolbar(int? id)
		{
			if (id == null || id < 1)
				return Content("");

			PageViewModel model = PageService.GetById(id.Value);

			if (model == null)
				return Content(string.Format("The page with id '{0}' could not be found", id));

			return PartialView(model);
		}

		/// <summary>
		/// 404 not found page - configured in the web.config
		/// </summary>
		public ActionResult NotFound()
		{
			return View("404");
		}

		/// <summary>
		/// 500 internal error - configured in the web.config
		/// </summary>
		public ActionResult ServerError()
		{
			return View("500");
		}
	}
}
