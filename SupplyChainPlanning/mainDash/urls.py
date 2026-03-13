from django.urls import path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from . import views

urlpatterns = [
    path("", views.index_case_study, name="index_case_study"),
    path("scan_supply_chain/", views.scan_supply_chain, name='scan_supply_chain'),
    path("run_simulation/", views.run_simulation, name='run_simulation'),
    path("generate_plan/", views.generate_plan, name='generate_plan'),
    path("simulate_plan/", views.simulate_plan, name='simulate_plan'),
    path("deterministic_results/", views.deterministic_results, name='deterministic_results'),
    path("scan_based_simulation_results/", views.scan_based_simulation_results, name='scan_based_simulation_results'),
    path("monte_carlo_results/", views.monte_carlo_results, name='monte_carlo_results'),
    path("scan_cyber_layer/", views.scan_cyber_layer, name='scan_cyber_layer'),
    path('get-suppliers/<int:part_id>/', views.get_suppliers_for_part, name='get_suppliers_for_part'),
    path('scan-analysis/', views.scan_analysis, name='scan_analysis'),
    path('perform_analysis_view/', views.perform_analysis_view, name='perform_analysis_view'),
    path("get_dropdown_data/", views.get_dropdown_data, name="get_dropdown_data"),
    path("detail/analysis/", views.detail, name="detail"),
    path('upload-csv/load_project/', views.load_project, name='load_project'),
    path('upload-csv/generate_data/', views.generate_data, name='generate_data'),
    path('upload-csv/data/', views.upload_case_parts_data, name='upload_case_parts_data'),
    path('upload-csv/data_suppliers/', views.upload_case_supplier_data, name='upload_case_supplier_data'),
    path('upload-csv/materials/', views.upload_material_data, name='upload_material_data'),
]

urlpatterns += staticfiles_urlpatterns()
