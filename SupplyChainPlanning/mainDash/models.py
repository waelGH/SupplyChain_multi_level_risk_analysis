from django.db import models
import datetime


class Case_system(models.Model):
    case_name = models.CharField(max_length=200)
    case_description = models.TextField()
    date_created = models.DateTimeField("date created", auto_now_add=True)

    def __str__(self):
        return self.case_name

class Component(models.Model):
    component_name = models.CharField(max_length=200)
    component_description = models.TextField()
    case_system = models.ForeignKey(Case_system, on_delete=models.CASCADE)
    date_created = models.DateTimeField("date created", auto_now_add=True)

    def __str__(self):
        return self.component_name

class Part(models.Model):
    part_name = models.CharField(max_length=200)
    part_description = models.TextField()
    part_number = models.CharField(max_length=100, default="")
    date_req = models.DateTimeField("date required")
    criticality = models.IntegerField(default=0)
    quantity = models.IntegerField(default=0)
    NAIC_code = models.CharField(max_length=6, default="")
    HS_code = models.CharField(max_length=6, default="")

    component = models.ForeignKey(Component, on_delete=models.CASCADE)
    date_created = models.DateTimeField("date created", auto_now_add=True)

    def __str__(self):
        return self.part_name

class PartSupplier(models.Model):
    part = models.ForeignKey(Part, on_delete=models.CASCADE)
    supplier_name = models.CharField(max_length=200)
    Lat = models.FloatField(max_length=20, default=0)
    Lon = models.FloatField(max_length=20, default=0)
    country = models.CharField(max_length=100, default="")
    quality = models.IntegerField(default=0)
    delay_risk = models.IntegerField(default=0)
    date_created = models.DateTimeField("date created", auto_now_add=True)
    NAIC_code = models.CharField(max_length=6, default="")
    HS_code = models.CharField(max_length=6, default="")
    production_time_days = models.IntegerField(default=0)
    shipping_time_days = models.IntegerField(default=0)


    def __str__(self):
        return f"{self.part.part_name} - {self.supplier_name}"
    
class Material(models.Model):
    material_name = models.CharField(max_length=200)
    material_description = models.TextField()
    quantity = models.IntegerField(default=0)
    date_req = models.DateTimeField("date required")
    criticality = models.IntegerField(default=0)
    part = models.ForeignKey(Part, on_delete=models.CASCADE)
    date_created = models.DateTimeField("date created", auto_now_add=True)
    
    def __str__(self):
        return self.material_name
    
class MaterialSupplier(models.Model):
    material = models.ForeignKey(Material, on_delete=models.CASCADE)
    supplier_name = models.CharField(max_length=200)
    Lat = models.FloatField(max_length=20, default=0)
    Lon = models.FloatField(max_length=20, default=0)
    country = models.CharField(max_length=100, default="")
    quality = models.IntegerField(default=0)
    delay_risk = models.IntegerField(default=0)
    date_created = models.DateTimeField("date created", auto_now_add=True)
    NAIC_code = models.CharField(max_length=6, default="")
    HS_code = models.CharField(max_length=6, default="")
    production_time_days = models.IntegerField(default=0)
    shipping_time_days = models.IntegerField(default=0)
    
    def __str__(self):
        return f"{self.material.material_name} - {self.supplier_name}"
    
class ComponentSupplier(models.Model):
    component = models.ForeignKey('Component', on_delete=models.CASCADE, null=True, blank=True)
    supplier_name = models.CharField(max_length=200)
    Lat = models.FloatField(max_length=20, default=0)
    Lon = models.FloatField(max_length=20, default=0)
    country = models.CharField(max_length=100, default="")
    date_created = models.DateTimeField("date created", auto_now_add=True)
    NAIC_code = models.CharField(max_length=6, default="")
    HS_code = models.CharField(max_length=6, default="")
    production_time_days = models.IntegerField(default=0)
    shipping_time_days = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.component.component_name} - {self.supplier_name}"
    
