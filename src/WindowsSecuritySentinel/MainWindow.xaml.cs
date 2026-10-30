using System.Windows;
using WindowsSecuritySentinel.ViewModels;

namespace WindowsSecuritySentinel;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
