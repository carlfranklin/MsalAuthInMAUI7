using Foundation;
using UIKit;
using Microsoft.Identity.Client;

namespace MsalAuthInMaui
{
    [Register("AppDelegate")]
    public class AppDelegate : MauiUIApplicationDelegate
    {
        protected override MauiApp CreateMauiApp() => MauiProgram.CreateMauiApp();
    }
}